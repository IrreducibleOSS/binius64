// Copyright 2025 Irreducible Inc.

use std::sync::Once;

use binius_core::{
	constraint_system::{AndConstraint, ConstraintSystem, MulConstraint, ValueVec},
	word::Word,
};
use binius_field::{BinaryField, Field};
use binius_frontend::{
	circuits::{
		jwt_claims::{Attribute, JwtClaims},
		sha256::Sha256,
	},
	compiler::CircuitBuilder,
	constraint_verifier::{eval_operand, verify_constraints},
};
use binius_math::{
	BinarySubspace,
	inner_product::{inner_product, inner_product_buffers},
	multilinear::eq::eq_ind_partial_eval,
	univariate::lagrange_evals,
};
use binius_prover::{
	fold_word::fold_words,
	protocols::shift::{OperatorData, build_key_collection, prove},
};
use binius_transcript::ProverTranscript;
use binius_utils::checked_arithmetics::strict_log_2;
use binius_verifier::{
	config::{LOG_WORD_SIZE_BITS, StdChallenger},
	evaluate_public_mle,
	protocols::shift::{OperatorData as VerifierOperatorData, verify},
};
use itertools::Itertools;
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256 as Sha256Hasher};

// Initialize tracing subscriber once for all tests
static INIT_TRACING: Once = Once::new();

fn init_tracing() {
	INIT_TRACING.call_once(|| {
		// Initialize tracing with profile layer - the guard is kept alive until program ends
		let _guard = tracing_profile::init_tracing().unwrap();
		// Note: In a real application you'd want to keep the guard alive
		// but for tests this is sufficient
		std::mem::forget(_guard);
	});
}

// Create example constraint systems with witnesses.

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

	(circuit.constraint_system().clone(), witness_filler.into_value_vec())
}

pub fn create_sha256_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	let builder = CircuitBuilder::new();
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
	let sha256 = Sha256::new(&builder, max_len, len, digest, message);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Populate with concrete message: "abc"
	let message_bytes = b"abc";
	sha256.populate_len(&mut witness_filler, message_bytes.len());
	sha256.populate_message(&mut witness_filler, message_bytes);

	// Calculate SHA256 digest of the message dynamically
	let hash = Sha256Hasher::digest(message_bytes);
	let expected_digest: [u8; 32] = hash.into();
	sha256.populate_digest(&mut witness_filler, expected_digest);

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system().clone(), witness_filler.into_value_vec())
}

pub fn create_base64_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::{circuits::base64::Base64UrlSafe, compiler::Wire};

	let builder = CircuitBuilder::new();
	let max_len_decoded: usize = 1368 * 5; // Must be multiple of 24

	// Create wires for Base64 circuit
	let decoded: Vec<Wire> = (0..max_len_decoded / 8)
		.map(|_| builder.add_inout())
		.collect();
	let encoded: Vec<Wire> = (0..max_len_decoded / 6)
		.map(|_| builder.add_inout())
		.collect();
	let len_decoded = builder.add_inout();

	// Create the Base64 circuit
	let base64 = Base64UrlSafe::new(&builder, max_len_decoded, decoded, encoded, len_decoded);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	let decoded_data = br#"Lorem ipsum dolor sit amet consectetur adipiscing elit quisque faucibus ex sapien vitae pellentesque sem placerat in id cursus mi pretium tellus duis convallis tempus leo eu aenean sed diam urna tempor pulvinar vivamus fringilla lacus nec metus bibendum egestas iaculis massa nisl malesuada lacinia integer nunc posuere ut hendrerit semper vel class aptent taciti sociosqu ad litora torquent per conubia nostra inceptos himenaeos orci various natoque penatibus"#;
	let encoded_data = br#"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQgY29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0IHF1aXNxdWUgZmF1Y2lidXMgZXggc2FwaWVuIHZpdGFlIHBlbGxlbnRlc3F1ZSBzZW0gcGxhY2VyYXQgaW4gaWQgY3Vyc3VzIG1pIHByZXRpdW0gdGVsbHVzIGR1aXMgY29udmFsbGlzIHRlbXB1cyBsZW8gZXUgYWVuZWFuIHNlZCBkaWFtIHVybmEgdGVtcG9yIHB1bHZpbmFyIHZpdmFtdXMgZnJpbmdpbGxhIGxhY3VzIG5lYyBtZXR1cyBiaWJlbmR1bSBlZ2VzdGFzIGlhY3VsaXMgbWFzc2EgbmlzbCBtYWxlc3VhZGEgbGFjaW5pYSBpbnRlZ2VyIG51bmMgcG9zdWVyZSB1dCBoZW5kcmVyaXQgc2VtcGVyIHZlbCBjbGFzcyBhcHRlbnQgdGFjaXRpIHNvY2lvc3F1IGFkIGxpdG9yYSB0b3JxdWVudCBwZXIgY29udWJpYSBub3N0cmEgaW5jZXB0b3MgaGltZW5hZW9zIG9yY2kgdmFyaW91cyBuYXRvcXVlIHBlbmF0aWJ1cw"#;

	base64.populate_len_decoded(&mut witness_filler, decoded_data.len());
	base64.populate_decoded(&mut witness_filler, decoded_data);
	base64.populate_encoded(&mut witness_filler, encoded_data);

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system().clone(), witness_filler.into_value_vec())
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
			data: (0..1).map(|_| builder.add_witness()).collect(),
			max_len: 8,
		},
		Term {
			len: builder.add_witness(),
			data: (0..1).map(|_| builder.add_witness()).collect(),
			max_len: 8,
		},
		Term {
			len: builder.add_witness(),
			data: (0..1).map(|_| builder.add_witness()).collect(),
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

	(circuit.constraint_system().clone(), witness_filler.into_value_vec())
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

	(circuit.constraint_system().clone(), witness_filler.into_value_vec())
}

pub fn create_rs256_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::{fixed_byte_vec::FixedByteVec, rs256::Rs256Verify};
	use rand::SeedableRng;
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
	let signature_bytes = FixedByteVec::new_inout(&builder, 256);
	let modulus_bytes = FixedByteVec::new_inout(&builder, 256);
	let message = FixedByteVec::new_witness(&builder, max_message_len);

	// Create the RS256 circuit with new API (only 4 arguments)
	let rs256 = Rs256Verify::new(&mut builder, message, signature_bytes, modulus_bytes);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Generate real RSA signature and witness data (following the working test pattern)
	let mut rng = StdRng::seed_from_u64(0);
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

	(circuit.constraint_system().clone(), witness_filler.into_value_vec())
}

// Compute the image of the witness applied to the AND constraints
pub fn compute_bitand_images(constraints: &[AndConstraint], witness: &ValueVec) -> [Vec<Word>; 3] {
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
fn evaluate_image<F: BinaryField>(image: &[Word], r_zhat_prime: F, r_x_prime_tensor: &[F]) -> F {
	let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS).unwrap();
	let l_tilde = lagrange_evals(&subspace, r_zhat_prime);
	let univariate = image
		.iter()
		.map(|&word| {
			(0..64)
				.filter(|&i| (word >> i) & Word::ONE == Word::ONE)
				.map(|i| l_tilde[i as usize])
				.sum()
		})
		.collect::<Vec<_>>();
	inner_product(r_x_prime_tensor.iter().copied(), univariate.iter().copied())
}

/// Compute inner product of tensor with all bits from words
pub fn evaluate_witness<F: Field>(words: &[Word], r_jr_y: &[F]) -> F {
	let (r_j, r_y) = r_jr_y.split_at(LOG_WORD_SIZE_BITS);

	let r_j_tensor = eq_ind_partial_eval::<F>(r_j);
	let r_y_tensor = eq_ind_partial_eval::<F>(r_y);

	let r_j_witness = fold_words::<_, F>(words, r_j_tensor.as_ref());

	inner_product_buffers(&r_j_witness, &r_y_tensor)
}

#[test]
fn test_prove_and_verify() {
	// Initialize tracing to capture instrumented function calls
	init_tracing();

	use binius_field::{BinaryField128bGhash, PackedBinaryGhash1x128b, Random};
	type F = BinaryField128bGhash;
	type P = PackedBinaryGhash1x128b;
	let mut rng = StdRng::seed_from_u64(0);

	let mut constraint_systems_to_test = vec![
		create_sha256_cs_with_witness(),
		create_jwt_claims_cs_with_witness(),
		create_rs256_cs_with_witness(),
		create_slice_cs_with_witness(),
		create_base64_cs_with_witness(),
		create_concat_cs_with_witness(),
	];
	for (constraint_system, _) in constraint_systems_to_test.iter_mut() {
		constraint_system.validate_and_prepare().unwrap();
	}

	for (i, (cs, value_vec)) in constraint_systems_to_test.into_iter().enumerate() {
		let circuit_name = match i {
			0 => "sha256",
			1 => "jwt_claims",
			2 => "rs256",
			3 => "slice",
			4 => "base64",
			5 => "concat",
			_ => "unknown",
		};

		// Validate constraints using frontend verifier first
		if let Err(e) = verify_constraints(&cs, &value_vec) {
			panic!("Circuit {circuit_name} failed constraint validation: {e}");
		}

		// Sample multilinear challenge point
		let r_x_prime_bitand = {
			let log_bitand_constraint_count = strict_log_2(cs.and_constraints.len()).unwrap();
			(0..log_bitand_constraint_count as u128)
				.map(F::new)
				.collect::<Vec<_>>()
		};
		let r_x_prime_intmul = {
			let log_intmul_constraint_count = strict_log_2(cs.mul_constraints.len()).unwrap();
			(0..log_intmul_constraint_count as u128)
				.map(F::new)
				.collect::<Vec<_>>()
		};

		// Sample univaraite eval point
		let r_zhat_prime_bitand = F::random(&mut rng);
		let r_zhat_prime_intmul = F::random(&mut rng);

		let bitand_evals = compute_bitand_images(&cs.and_constraints, &value_vec).map(|image| {
			evaluate_image(
				&image,
				r_zhat_prime_bitand,
				eq_ind_partial_eval(&r_x_prime_bitand).as_ref(),
			)
		});

		let intmul_evals = compute_intmul_images(&cs.mul_constraints, &value_vec).map(|image| {
			evaluate_image(
				&image,
				r_zhat_prime_intmul,
				eq_ind_partial_eval(&r_x_prime_intmul).as_ref(),
			)
		});

		// Build prover's constraint system
		let key_collection = build_key_collection(&cs);

		// Create prover transcript and call the prover
		let mut prover_transcript = ProverTranscript::<StdChallenger>::default();

		let prover_bitand_data =
			OperatorData::new(r_zhat_prime_bitand, r_x_prime_bitand.clone(), bitand_evals.to_vec());
		let prover_intmul_data =
			OperatorData::new(r_zhat_prime_intmul, r_x_prime_intmul.clone(), intmul_evals.to_vec());

		let inout_n_vars = strict_log_2(cs.value_vec_layout.offset_witness).unwrap();

		let prover_output = prove::<F, P, StdChallenger>(
			inout_n_vars,
			&key_collection,
			value_vec.combined_witness(),
			prover_bitand_data.clone(),
			prover_intmul_data.clone(),
			&mut prover_transcript,
		)
		.unwrap();

		// Create verifier transcript and call the verifier
		let mut verifier_transcript = prover_transcript.into_verifier();

		let verifier_bitand_data =
			VerifierOperatorData::new(r_zhat_prime_bitand, r_x_prime_bitand, bitand_evals);
		let verifier_intmul_data =
			VerifierOperatorData::new(r_zhat_prime_intmul, r_x_prime_intmul, intmul_evals);

		let verifier_output =
			verify(&cs, verifier_bitand_data, verifier_intmul_data, &mut verifier_transcript)
				.unwrap();

		// Compute the expected public input evaluation
		let z_coords = verifier_output.eval_point[..LOG_WORD_SIZE_BITS].to_vec();
		let y_coords = verifier_output.eval_point
			[LOG_WORD_SIZE_BITS..LOG_WORD_SIZE_BITS + inout_n_vars]
			.to_vec();
		let expected_public_eval = evaluate_public_mle(value_vec.public(), &z_coords, &y_coords);
		// and check consistency with verifier output
		assert_eq!(expected_public_eval, verifier_output.public_eval);

		// Check the claimed eval matches the computed eval
		let expected_eval =
			evaluate_witness(value_vec.combined_witness(), &verifier_output.eval_point);
		assert_eq!(expected_eval, verifier_output.witness_eval);

		// Check consistency of prover and verifier outputs
		assert_eq!(prover_output.challenges, verifier_output.eval_point);
		assert_eq!(prover_output.eval, verifier_output.witness_eval);
	}
}
