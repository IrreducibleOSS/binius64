// Copyright 2025 Irreducible Inc.

use std::sync::Once;

use binius_field::Field;
use binius_frontend::{
	circuits::jwt_claims::{Attribute, JwtClaims},
	compiler::CircuitBuilder,
	constraint_system::{
		AndConstraint, ConstraintSystem, MulConstraint, ShiftVariant, ShiftedValueIndex, ValueVec,
		ValueVecLayout,
	},
	constraint_verifier::{eval_operand, verify_constraints},
	word::Word,
};
use binius_math::univariate::lagrange_evals;
use binius_transcript::ProverTranscript;
use binius_utils::checked_arithmetics::strict_log_2;
use binius_verifier::{
	config::StdChallenger,
	protocols::shift::{
		OperatorData as VerifierOperatorData, WORD_SIZE_BITS,
		inner_product as inner_product_scalar, tensor_expand as tensor_expand_scalar, verify,
	},
};
use itertools::Itertools;
use rand::{SeedableRng, rngs::StdRng};

use super::{
	prove::{OperatorData as ProverOperatorData, prove},
	record::{build_record_for_bitmul_constraints, build_record_for_intmul_constraints},
	utils::naive_witness_evaluation,
};

// Initialize tracing subscriber once for all tests
static INIT_TRACING: Once = Once::new();

use std::cell::RefCell;

thread_local! {
	static CHROME_GUARD: RefCell<Option<tracing_chrome::FlushGuard>> = RefCell::new(None);
}

fn init_tracing() {
	INIT_TRACING.call_once(|| {
		// Create chrome trace layer for trace file generation
		let (chrome_layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
			.file("trace.json")
			.include_args(true)
			.build();

		// Store guard in thread-local storage
		CHROME_GUARD.with(|g| {
			*g.borrow_mut() = Some(guard);
		});

		use tracing_subscriber::prelude::*;
		tracing_subscriber::registry().with(chrome_layer).init();
	});
}

// Function to manually flush trace at end of test
fn flush_trace() {
	CHROME_GUARD.with(|g| {
		if let Some(guard) = g.borrow_mut().take() {
			drop(guard); // This should flush the trace
		}
	});
}

// Create example constraint systems with witnesses.
// Only ZKLogin presented trouble and is now removed, the constraints didn't seem to validate.
// Seems these constraint systems don't use MUL constraints, only AND constraints.

pub fn create_jwt_claims_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	let builder = CircuitBuilder::new();
	let max_len_json = 128;
	let len_json = builder.add_witness();
	let json: Vec<binius_frontend::compiler::Wire> = (0..max_len_json / 8)
		.map(|_| builder.add_witness())
		.collect();

	let attributes = vec![
		Attribute {
			name: "iss",
			len_value: builder.add_inout(),
			value: (0..32 / 8).map(|_| builder.add_inout()).collect(),
		},
		Attribute {
			name: "sub",
			len_value: builder.add_inout(),
			value: (0..32 / 8).map(|_| builder.add_inout()).collect(),
		},
	];

	let jwt_claims = JwtClaims::new(&builder, max_len_json, len_json, json, attributes);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Populate with concrete JSON
	let json_str = r#"{"iss":"example.com","sub":"user123"}"#;
	jwt_claims.populate_len_json(&mut witness_filler, json_str.len());
	jwt_claims.populate_json(&mut witness_filler, json_str.as_bytes());

	// Populate expected attribute values
	jwt_claims.attributes[0].populate_len_value(&mut witness_filler, 11); // "example.com"
	jwt_claims.attributes[0].populate_value(&mut witness_filler, b"example.com");

	jwt_claims.attributes[1].populate_len_value(&mut witness_filler, 7); // "user123"
	jwt_claims.attributes[1].populate_value(&mut witness_filler, b"user123");

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

pub fn create_sha256_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::sha256::Sha256;

	let mut builder = CircuitBuilder::new();
	let max_len: usize = 64; // Maximum message length in bytes

	// Create wires for the SHA256 circuit
	let len = builder.add_witness(); // Actual message length
	let digest = [
		builder.add_inout(), // Expected digest as 4x64-bit words
		builder.add_inout(),
		builder.add_inout(),
		builder.add_inout(),
	];
	let message: Vec<binius_frontend::compiler::Wire> = (0..max_len.div_ceil(8))
		.map(|_| builder.add_witness())
		.collect();

	// Create the SHA256 circuit
	let sha256 = Sha256::new(&mut builder, max_len, len, digest, message);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Populate with concrete message: "abc"
	let message_bytes = b"abc";
	sha256.populate_len(&mut witness_filler, message_bytes.len());
	sha256.populate_message(&mut witness_filler, message_bytes);

	// SHA256 digest of "abc"
	let expected_digest = [
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
		0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
		0x15, 0xad,
	];
	sha256.populate_digest(&mut witness_filler, expected_digest);

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

pub fn create_base64_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::base64::Base64UrlSafe;

	let builder = CircuitBuilder::new();
	let max_len_decoded: usize = 1368 * 2; // Must be multiple of 24

	// Create wires for Base64 circuit
	let decoded: Vec<binius_frontend::compiler::Wire> = (0..max_len_decoded / 8)
		.map(|_| builder.add_inout())
		.collect();
	let encoded: Vec<binius_frontend::compiler::Wire> = (0..max_len_decoded / 6)
		.map(|_| builder.add_inout())
		.collect();
	let len_decoded = builder.add_inout();

	// Create the Base64 circuit
	let base64 = Base64UrlSafe::new(&builder, max_len_decoded, decoded, encoded, len_decoded);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Test with large text for scaling up the constraint system
	let decoded_data = br#"We and our partners store and/or access information on a device, such as cookies and process personal data, such as unique identifiers and standard information sent by a device for personalised advertising and content, advertising and content measurement, audience research and services development.With your permission we and our partners may use precise geolocation data and identification through device scanning. You may click to consent to our and our 1508 partners' processing as described above. Alternatively you may click to refuse to consent or access more detailed information and change your preferences before consenting. Please note that some processing of your personal data may not require your consent, but you have a right to object to such processing.Your preferences will apply to this website only and will be stored in IABGPP_HDR_GppString cookie for 13 months. You can change your preferences or withdraw your consent at any time by returning to this site and clicking the "Privacy" button at the bottom of the webpage. Please note that this website/app uses one or more Google services and may gather and store information including but not limited to your visit or usage behaviour. You may click to grant or deny consent to Google and its third-party tags to use your data for below specified purposes in below Google consent section. We and our partners store and/or access information on a device, such as cookies and process personal data, such as unique identifiers and standard information sent by a device for personalised advertising and content, advertising and content measurement, audience research and services development.With your permission we and our partners may use precise geolocation data and identification through device scanning. You may click to consent to our and our 1508 partners' processing as described above. Alternatively you may click to refuse to consent or access more detailed information and change your preferences before consenting. Please note that some processing of your personal data may not require your consent, but you have a right to object to such processing.Your preferences will apply to this website only and will be stored in IABGPP_HDR_GppString cookie for 13 months. You can change your preferences or withdraw your consent at any time by returning to this site and clicking the "Privacy" button at the bottom of the webpage. Please note that this website/app uses one or more Google services and may gather and store information including but not limited to your visit or usage behaviour. You may click to grant or deny consent to Google and its third-party tags to use your data for below specified purposes in below Google consent section."#;
	let encoded_data = b"V2UgYW5kIG91ciBwYXJ0bmVycyBzdG9yZSBhbmQvb3IgYWNjZXNzIGluZm9ybWF0aW9uIG9uIGEgZGV2aWNlLCBzdWNoIGFzIGNvb2tpZXMgYW5kIHByb2Nlc3MgcGVyc29uYWwgZGF0YSwgc3VjaCBhcyB1bmlxdWUgaWRlbnRpZmllcnMgYW5kIHN0YW5kYXJkIGluZm9ybWF0aW9uIHNlbnQgYnkgYSBkZXZpY2UgZm9yIHBlcnNvbmFsaXNlZCBhZHZlcnRpc2luZyBhbmQgY29udGVudCwgYWR2ZXJ0aXNpbmcgYW5kIGNvbnRlbnQgbWVhc3VyZW1lbnQsIGF1ZGllbmNlIHJlc2VhcmNoIGFuZCBzZXJ2aWNlcyBkZXZlbG9wbWVudC5XaXRoIHlvdXIgcGVybWlzc2lvbiB3ZSBhbmQgb3VyIHBhcnRuZXJzIG1heSB1c2UgcHJlY2lzZSBnZW9sb2NhdGlvbiBkYXRhIGFuZCBpZGVudGlmaWNhdGlvbiB0aHJvdWdoIGRldmljZSBzY2FubmluZy4gWW91IG1heSBjbGljayB0byBjb25zZW50IHRvIG91ciBhbmQgb3VyIDE1MDggcGFydG5lcnMnIHByb2Nlc3NpbmcgYXMgZGVzY3JpYmVkIGFib3ZlLiBBbHRlcm5hdGl2ZWx5IHlvdSBtYXkgY2xpY2sgdG8gcmVmdXNlIHRvIGNvbnNlbnQgb3IgYWNjZXNzIG1vcmUgZGV0YWlsZWQgaW5mb3JtYXRpb24gYW5kIGNoYW5nZSB5b3VyIHByZWZlcmVuY2VzIGJlZm9yZSBjb25zZW50aW5nLiBQbGVhc2Ugbm90ZSB0aGF0IHNvbWUgcHJvY2Vzc2luZyBvZiB5b3VyIHBlcnNvbmFsIGRhdGEgbWF5IG5vdCByZXF1aXJlIHlvdXIgY29uc2VudCwgYnV0IHlvdSBoYXZlIGEgcmlnaHQgdG8gb2JqZWN0IHRvIHN1Y2ggcHJvY2Vzc2luZy5Zb3VyIHByZWZlcmVuY2VzIHdpbGwgYXBwbHkgdG8gdGhpcyB3ZWJzaXRlIG9ubHkgYW5kIHdpbGwgYmUgc3RvcmVkIGluIElBQkdQUF9IRFJfR3BwU3RyaW5nIGNvb2tpZSBmb3IgMTMgbW9udGhzLiBZb3UgY2FuIGNoYW5nZSB5b3VyIHByZWZlcmVuY2VzIG9yIHdpdGhkcmF3IHlvdXIgY29uc2VudCBhdCBhbnkgdGltZSBieSByZXR1cm5pbmcgdG8gdGhpcyBzaXRlIGFuZCBjbGlja2luZyB0aGUgIlByaXZhY3kiIGJ1dHRvbiBhdCB0aGUgYm90dG9tIG9mIHRoZSB3ZWJwYWdlLiBQbGVhc2Ugbm90ZSB0aGF0IHRoaXMgd2Vic2l0ZS9hcHAgdXNlcyBvbmUgb3IgbW9yZSBHb29nbGUgc2VydmljZXMgYW5kIG1heSBnYXRoZXIgYW5kIHN0b3JlIGluZm9ybWF0aW9uIGluY2x1ZGluZyBidXQgbm90IGxpbWl0ZWQgdG8geW91ciB2aXNpdCBvciB1c2FnZSBiZWhhdmlvdXIuIFlvdSBtYXkgY2xpY2sgdG8gZ3JhbnQgb3IgZGVueSBjb25zZW50IHRvIEdvb2dsZSBhbmQgaXRzIHRoaXJkLXBhcnR5IHRhZ3MgdG8gdXNlIHlvdXIgZGF0YSBmb3IgYmVsb3cgc3BlY2lmaWVkIHB1cnBvc2VzIGluIGJlbG93IEdvb2dsZSBjb25zZW50IHNlY3Rpb24uIFdlIGFuZCBvdXIgcGFydG5lcnMgc3RvcmUgYW5kL29yIGFjY2VzcyBpbmZvcm1hdGlvbiBvbiBhIGRldmljZSwgc3VjaCBhcyBjb29raWVzIGFuZCBwcm9jZXNzIHBlcnNvbmFsIGRhdGEsIHN1Y2ggYXMgdW5pcXVlIGlkZW50aWZpZXJzIGFuZCBzdGFuZGFyZCBpbmZvcm1hdGlvbiBzZW50IGJ5IGEgZGV2aWNlIGZvciBwZXJzb25hbGlzZWQgYWR2ZXJ0aXNpbmcgYW5kIGNvbnRlbnQsIGFkdmVydGlzaW5nIGFuZCBjb250ZW50IG1lYXN1cmVtZW50LCBhdWRpZW5jZSByZXNlYXJjaCBhbmQgc2VydmljZXMgZGV2ZWxvcG1lbnQuV2l0aCB5b3VyIHBlcm1pc3Npb24gd2UgYW5kIG91ciBwYXJ0bmVycyBtYXkgdXNlIHByZWNpc2UgZ2VvbG9jYXRpb24gZGF0YSBhbmQgaWRlbnRpZmljYXRpb24gdGhyb3VnaCBkZXZpY2Ugc2Nhbm5pbmcuIFlvdSBtYXkgY2xpY2sgdG8gY29uc2VudCB0byBvdXIgYW5kIG91ciAxNTA4IHBhcnRuZXJzJyBwcm9jZXNzaW5nIGFzIGRlc2NyaWJlZCBhYm92ZS4gQWx0ZXJuYXRpdmVseSB5b3UgbWF5IGNsaWNrIHRvIHJlZnVzZSB0byBjb25zZW50IG9yIGFjY2VzcyBtb3JlIGRldGFpbGVkIGluZm9ybWF0aW9uIGFuZCBjaGFuZ2UgeW91ciBwcmVmZXJlbmNlcyBiZWZvcmUgY29uc2VudGluZy4gUGxlYXNlIG5vdGUgdGhhdCBzb21lIHByb2Nlc3Npbmcgb2YgeW91ciBwZXJzb25hbCBkYXRhIG1heSBub3QgcmVxdWlyZSB5b3VyIGNvbnNlbnQsIGJ1dCB5b3UgaGF2ZSBhIHJpZ2h0IHRvIG9iamVjdCB0byBzdWNoIHByb2Nlc3NpbmcuWW91ciBwcmVmZXJlbmNlcyB3aWxsIGFwcGx5IHRvIHRoaXMgd2Vic2l0ZSBvbmx5IGFuZCB3aWxsIGJlIHN0b3JlZCBpbiBJQUJHUFBfSERSX0dwcFN0cmluZyBjb29raWUgZm9yIDEzIG1vbnRocy4gWW91IGNhbiBjaGFuZ2UgeW91ciBwcmVmZXJlbmNlcyBvciB3aXRoZHJhdyB5b3VyIGNvbnNlbnQgYXQgYW55IHRpbWUgYnkgcmV0dXJuaW5nIHRvIHRoaXMgc2l0ZSBhbmQgY2xpY2tpbmcgdGhlICJQcml2YWN5IiBidXR0b24gYXQgdGhlIGJvdHRvbSBvZiB0aGUgd2VicGFnZS4gUGxlYXNlIG5vdGUgdGhhdCB0aGlzIHdlYnNpdGUvYXBwIHVzZXMgb25lIG9yIG1vcmUgR29vZ2xlIHNlcnZpY2VzIGFuZCBtYXkgZ2F0aGVyIGFuZCBzdG9yZSBpbmZvcm1hdGlvbiBpbmNsdWRpbmcgYnV0IG5vdCBsaW1pdGVkIHRvIHlvdXIgdmlzaXQgb3IgdXNhZ2UgYmVoYXZpb3VyLiBZb3UgbWF5IGNsaWNrIHRvIGdyYW50IG9yIGRlbnkgY29uc2VudCB0byBHb29nbGUgYW5kIGl0cyB0aGlyZC1wYXJ0eSB0YWdzIHRvIHVzZSB5b3VyIGRhdGEgZm9yIGJlbG93IHNwZWNpZmllZCBwdXJwb3NlcyBpbiBiZWxvdyBHb29nbGUgY29uc2VudCBzZWN0aW9uLg==";

	base64.populate_len_decoded(&mut witness_filler, decoded_data.len());
	base64.populate_decoded(&mut witness_filler, decoded_data);
	base64.populate_encoded(&mut witness_filler, encoded_data);

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

pub fn create_concat_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::concat::{Concat, Term};

	let builder = CircuitBuilder::new();
	let max_n_joined: usize = 32; // Maximum joined size

	// Create wires for concat circuit
	let len_joined = builder.add_inout();
	let joined: Vec<binius_frontend::compiler::Wire> =
		(0..max_n_joined / 8).map(|_| builder.add_inout()).collect();

	// Create terms: "Hello" + " " + "World!"
	let terms = vec![
		Term {
			len: builder.add_witness(),
			data: (0..8 / 8).map(|_| builder.add_witness()).collect(),
			max_len: 8,
		},
		Term {
			len: builder.add_witness(),
			data: (0..8 / 8).map(|_| builder.add_witness()).collect(),
			max_len: 8,
		},
		Term {
			len: builder.add_witness(),
			data: (0..8 / 8).map(|_| builder.add_witness()).collect(),
			max_len: 8,
		},
	];

	// Create the Concat circuit
	let concat = Concat::new(&builder, max_n_joined, len_joined, joined, terms);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Test data
	let term1_data = b"Hello";
	let term2_data = b" ";
	let term3_data = b"World!";
	let joined_data = b"Hello World!";

	// Populate terms
	concat.terms[0].populate_len(&mut witness_filler, term1_data.len());
	concat.terms[0].populate_data(&mut witness_filler, term1_data);

	concat.terms[1].populate_len(&mut witness_filler, term2_data.len());
	concat.terms[1].populate_data(&mut witness_filler, term2_data);

	concat.terms[2].populate_len(&mut witness_filler, term3_data.len());
	concat.terms[2].populate_data(&mut witness_filler, term3_data);

	// Populate joined result
	concat.populate_len_joined(&mut witness_filler, joined_data.len());
	concat.populate_joined(&mut witness_filler, joined_data);

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

pub fn create_slice_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::slice::Slice;

	let builder = CircuitBuilder::new();
	let max_n_input: usize = 32; // Maximum input size
	let max_n_slice: usize = 16; // Maximum slice size

	// Create wires for slice circuit
	let len_input = builder.add_witness();
	let len_slice = builder.add_witness();
	let input: Vec<binius_frontend::compiler::Wire> = (0..max_n_input / 8)
		.map(|_| builder.add_witness())
		.collect();
	let slice: Vec<binius_frontend::compiler::Wire> = (0..max_n_slice / 8)
		.map(|_| builder.add_witness())
		.collect();
	let offset = builder.add_witness();

	// Create the Slice circuit
	let slice_circuit =
		Slice::new(&builder, max_n_input, max_n_slice, len_input, len_slice, input, slice, offset);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Test slicing "Hello World!" from offset 6 with length 5 to get "World"
	let input_data = b"Hello World!";
	let slice_data = b"World";
	let offset_val = 6;

	slice_circuit.populate_len_input(&mut witness_filler, input_data.len());
	slice_circuit.populate_len_slice(&mut witness_filler, slice_data.len());
	slice_circuit.populate_input(&mut witness_filler, input_data);
	slice_circuit.populate_slice(&mut witness_filler, slice_data);
	slice_circuit.populate_offset(&mut witness_filler, offset_val);

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

pub fn create_rs256_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::{fixed_byte_vec::FixedByteVec, rs256::Rs256Verify};
	use rand::{SeedableRng, rngs::StdRng};
	// ... (rest of the code remains the same)
	use rsa::{
		RsaPrivateKey, RsaPublicKey,
		pkcs1v15::SigningKey,
		sha2::{Digest, Sha256},
		signature::{SignatureEncoding, Signer},
		traits::PublicKeyParts,
	};

	let mut builder = CircuitBuilder::new();
	let max_message_len: usize = 256; // Maximum message length

	// Setup circuit using the new Rs256Verify API
	let signature_bytes = FixedByteVec::new_inout(&mut builder, 256);
	let modulus_bytes = FixedByteVec::new_inout(&mut builder, 256);
	let message = FixedByteVec::new_witness(&mut builder, max_message_len);

	// Create the RS256 circuit with new API (only 4 arguments)
	let rs256 = Rs256Verify::new(&mut builder, message, signature_bytes, modulus_bytes);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Generate real RSA signature and witness data (following the working test pattern)
	let mut rng = StdRng::seed_from_u64(42);
	let bits = 2048;
	let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
	let public_key = RsaPublicKey::from(&private_key);

	let message_bytes = b"Test message for RS256 verification";
	let signing_key = SigningKey::<Sha256>::new(private_key);
	let signature_obj = signing_key.sign(message_bytes);

	// Get signature and modulus as byte arrays
	let signature_bytes = signature_obj.to_bytes();
	let modulus_bytes = public_key.n().to_be_bytes();

	// Populate using the exact same pattern as the working test
	let hash = Sha256::digest(message_bytes);
	rs256.populate_rsa(&mut witness_filler, &signature_bytes, &modulus_bytes);
	rs256.populate_message_len(&mut witness_filler, message_bytes.len());
	rs256.populate_message(&mut witness_filler, message_bytes);
	rs256
		.sha256
		.populate_digest(&mut witness_filler, hash.into());

	// Populate wire witness using built circuit
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

// Compute the image of the witness applied to the AND constraints
pub fn compute_bitmul_images(constraints: &[AndConstraint], witness: &ValueVec) -> [Vec<Word>; 3] {
	let (a_image, b_image, c_image) = constraints
		.iter()
		.map(|constraint| {
			let a = eval_operand(witness, &constraint.a);
			let b = eval_operand(witness, &constraint.b);
			let c = eval_operand(witness, &constraint.c);
			(a, b, c)
		})
		.multiunzip();
	[a_image, b_image, c_image]
}

// Compute the image of the witness applied to the MUL constraints
fn compute_intmul_images(constraints: &[MulConstraint], witness: &ValueVec) -> [Vec<Word>; 4] {
	let (a_image, b_image, hi_image, lo_image) = constraints
		.iter()
		.map(|constraint| {
			let a = eval_operand(witness, &constraint.a);
			let b = eval_operand(witness, &constraint.b);
			let hi = eval_operand(witness, &constraint.hi);
			let lo = eval_operand(witness, &constraint.lo);
			(a, b, hi, lo)
		})
		.multiunzip();
	[a_image, b_image, hi_image, lo_image]
}

// Evaluate the image of the witness applied to the AND or MUL constraints
// Univariate point is `r_zhat_prime`, multilinear point tensor-expanded is `r_x_prime_tensor`
fn evaluate_image<F: Field>(
	image: &[Word],
	univariate_domain: &[F],
	r_zhat_prime: F,
	r_x_prime_tensor: &[F],
) -> F {
	let l_tilde = lagrange_evals(univariate_domain, r_zhat_prime).unwrap();
	let univariate = image
		.iter()
		.map(|&word| {
			(0..64)
				.filter(|&i| (word >> i) & Word::ONE == Word::ONE)
				.map(|i| l_tilde[i as usize])
				.sum()
		})
		.collect::<Vec<_>>();
	inner_product_scalar(r_x_prime_tensor, &univariate)
}

#[test]
fn test_prove_and_verify() {
	// Initialize tracing to capture instrumented function calls
	init_tracing();

	use binius_field::{BinaryField128bGhash, PackedBinaryGhash1x128b, Random};
	type F = BinaryField128bGhash;
	type P = PackedBinaryGhash1x128b;
	let mut rng = StdRng::seed_from_u64(0);

	let constraint_systems_to_test = vec![
		create_sha256_cs_with_witness(),
		create_jwt_claims_cs_with_witness(),
		// RSA is relatively slow; only this one uses MUL constraints
		create_rs256_cs_with_witness(),
		// ZKLogin witness not populated; it's all zeros, so it trivially passes
		// create_zklogin_cs_with_witness(),
		create_slice_cs_with_witness(),
		create_base64_cs_with_witness(),
		create_concat_cs_with_witness(),
	];

	for (i, (cs, value_vec)) in constraint_systems_to_test.into_iter().enumerate() {
		// Validate constraints using frontend verifier first
		if let Err(e) = verify_constraints(&cs, &value_vec) {
			panic!("Circuit {} failed constraint validation: {}", i, e);
		}

		// Sample univaraite eval point
		let r_zhat_prime_bitmul = F::random(&mut rng);
		let r_zhat_prime_intmul = F::random(&mut rng);
		// Generate univariate skip domain
		let univariate_domain = (0..WORD_SIZE_BITS as u128).map(F::new).collect::<Vec<_>>();

		// Sample multilinear eval points
		let log_bitmul_constraint_count = strict_log_2(cs.and_constraints.len()).unwrap();
		let log_intmul_constraint_count = strict_log_2(cs.mul_constraints.len()).unwrap();

		let r_x_prime_bitmul = (0..log_bitmul_constraint_count as u128)
			.map(F::new)
			.collect::<Vec<_>>();
		let r_x_prime_intmul = (0..log_intmul_constraint_count as u128)
			.map(F::new)
			.collect::<Vec<_>>();

		let r_x_prime_bitmul_tensor: Vec<F> =
			tensor_expand_scalar(&r_x_prime_bitmul, r_x_prime_bitmul.len());
		let r_x_prime_intmul_tensor: Vec<F> =
			tensor_expand_scalar(&r_x_prime_intmul, r_x_prime_intmul.len());

		// Compute bitmul evals
		let bitmul_evals = compute_bitmul_images(&cs.and_constraints, &value_vec).map(|image| {
			evaluate_image(
				&image,
				&univariate_domain,
				r_zhat_prime_bitmul,
				&r_x_prime_bitmul_tensor,
			)
		});

		// Compute intmul evals
		let intmul_evals = compute_intmul_images(&cs.mul_constraints, &value_vec).map(|image| {
			evaluate_image(
				&image,
				&univariate_domain,
				r_zhat_prime_intmul,
				&r_x_prime_intmul_tensor,
			)
		});

		// Build records for the bitmul constraints
		let bitmul_records = build_record_for_bitmul_constraints(&cs);
		let intmul_records = build_record_for_intmul_constraints(&cs);

		// Create prover transcript and call the prover
		let mut prover_transcript = ProverTranscript::<StdChallenger>::default();

		let prover_bitmul_data = ProverOperatorData::new(
			bitmul_records,
			r_zhat_prime_bitmul,
			r_x_prime_bitmul.clone(),
			bitmul_evals,
		);
		let prover_intmul_data = ProverOperatorData::new(
			intmul_records,
			r_zhat_prime_intmul,
			r_x_prime_intmul.clone(),
			intmul_evals,
		);

		let inout_n_vars = strict_log_2(
			(cs.value_vec_layout.n_const + cs.value_vec_layout.n_inout).next_power_of_two(),
		)
		.unwrap();

		let prover_output = prove::<F, P, StdChallenger>(
			inout_n_vars,
			value_vec.combined_witness(),
			prover_bitmul_data.clone(),
			prover_intmul_data.clone(),
			&mut prover_transcript,
		)
		.unwrap();

		// Create verifier transcript and call the verifier
		let mut verifier_transcript = prover_transcript.into_verifier();

		let verifier_bitmul_data =
			VerifierOperatorData::new(r_x_prime_bitmul, r_zhat_prime_bitmul, bitmul_evals);
		let verifier_intmul_data =
			VerifierOperatorData::new(r_x_prime_intmul, r_zhat_prime_intmul, intmul_evals);

		let verifier_output =
			verify(cs, verifier_bitmul_data, verifier_intmul_data, &mut verifier_transcript)
				.unwrap();

		// Check prover and verifier agree
		assert_eq!(prover_output, verifier_output);

		// Check the claimed eval matches the computed eval
		let expected_eval =
			naive_witness_evaluation(&value_vec.combined_witness(), &verifier_output.challenges);
		assert_eq!(expected_eval, verifier_output.eval);
	}

	// Flush the trace file at the end of the test
	flush_trace();
}
