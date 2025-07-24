// Copyright 2025 Irreducible Inc.

use binius_frontend::{
	circuits::jwt_claims::{Attribute, JwtClaims},
	compiler::CircuitBuilder,
	constraint_system::{ConstraintSystem, ValueVec},
};

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
	let max_len_decoded: usize = 24; // Must be multiple of 24

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

	// Test with "Hello!" -> "SGVsbG8h" in base64
	let decoded_data = b"Hello!";
	let encoded_data = b"SGVsbG8h";

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

	// Generate real RSA signature and witness data (following the existing test pattern)
	let mut rng = StdRng::seed_from_u64(42);
	let bits = 2048;
	let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
	let public_key = RsaPublicKey::from(&private_key);

	let message_bytes = b"Test message for RS256 verification";
	let signing_key = SigningKey::<Sha256>::new(private_key);
	let signature_obj = signing_key.sign(message_bytes);

	// Get signature and modulus as byte arrays (not limbs)
	let signature_bytes = signature_obj.to_bytes();
	let modulus_bytes = public_key.n().to_be_bytes();

	// Use the new populate_rsa method and other public methods
	let hash = Sha256::digest(message_bytes);
	rs256.populate_rsa(&mut witness_filler, &signature_bytes, &modulus_bytes);
	rs256.populate_message_len(&mut witness_filler, message_bytes.len());
	rs256.populate_message(&mut witness_filler, message_bytes);
	rs256
		.sha256
		.populate_digest(&mut witness_filler, hash.into());

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}
