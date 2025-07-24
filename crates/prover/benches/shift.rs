// Copyright 2025 Irreducible Inc.

use std::hint::black_box;

use binius_field::Field;
use binius_frontend::{
	compiler::CircuitBuilder,
	constraint_system::{AndConstraint, ConstraintSystem, MulConstraint, ValueVec},
	constraint_verifier::{eval_operand, verify_constraints},
	word::Word,
};
use binius_math::univariate::lagrange_evals;
use binius_prover::protocols::shift::{
	OperatorData as ProverOperatorData, build_record_for_bitmul_constraints,
	build_record_for_intmul_constraints, prove,
};
use binius_transcript::ProverTranscript;
use binius_utils::checked_arithmetics::strict_log_2;
use binius_verifier::{
	config::StdChallenger,
	protocols::shift::{
		OperatorData as VerifierOperatorData, WORD_SIZE_BITS,
		inner_product as inner_product_scalar, tensor_expand as tensor_expand_scalar, verify,
	},
};
use criterion::{Criterion, criterion_group, criterion_main};
use itertools::Itertools;
use rand::{SeedableRng, rngs::StdRng};

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

fn bench_prove_and_verify(c: &mut Criterion) {
	use binius_field::{BinaryField128bGhash, PackedBinaryGhash1x128b, Random};
	type F = BinaryField128bGhash;
	type P = PackedBinaryGhash1x128b;
	let mut rng = StdRng::seed_from_u64(0);

	let constraint_systems_to_test = vec![
		// ("sha256", create_sha256_cs_with_witness()),
		// ("jwt_claims", create_jwt_claims_cs_with_witness()),
		("rs256", create_rs256_cs_with_witness()),
		// ("slice", create_slice_cs_with_witness()),
		// ("base64", create_base64_cs_with_witness()),
		// ("concat", create_concat_cs_with_witness()),
	];

	for (name, (cs, value_vec)) in constraint_systems_to_test {
		// Validate constraints using frontend verifier first
		if let Err(e) = verify_constraints(&cs, &value_vec) {
			panic!("Circuit {} failed constraint validation: {}", name, e);
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

		let verifier_bitmul_data =
			VerifierOperatorData::new(r_x_prime_bitmul, r_zhat_prime_bitmul, bitmul_evals);
		let verifier_intmul_data =
			VerifierOperatorData::new(r_x_prime_intmul, r_zhat_prime_intmul, intmul_evals);

		let inout_n_vars = strict_log_2(
			(cs.value_vec_layout.n_const + cs.value_vec_layout.n_inout).next_power_of_two(),
		)
		.unwrap();

		// Benchmark the prover
		c.bench_function(&format!("{}_prove", name), |b| {
			// Create prover transcript and call the prover

			b.iter_with_setup(
				|| (prover_bitmul_data.clone(), prover_intmul_data.clone()),
				|(prover_bitmul_data, prover_intmul_data)| {
					let mut prover_transcript = ProverTranscript::<StdChallenger>::default();
					// Hot loop: only the actual proving work
					black_box(
						prove::<F, P, StdChallenger>(
							inout_n_vars,
							value_vec.combined_witness(),
							prover_bitmul_data,
							prover_intmul_data,
							&mut prover_transcript,
						)
						.unwrap(),
					)
				},
			)
		});

		// Pre-run the prover to get the transcript for verifier benchmarking
		let mut setup_prover_transcript = ProverTranscript::<StdChallenger>::default();
		let _setup_prover_output = prove::<F, P, StdChallenger>(
			inout_n_vars,
			value_vec.combined_witness(),
			prover_bitmul_data.clone(),
			prover_intmul_data.clone(),
			&mut setup_prover_transcript,
		)
		.unwrap();
		let setup_verifier_transcript = setup_prover_transcript.into_verifier();

		// Benchmark the verifier
		c.bench_function(&format!("{}_verify", name), |b| {
			b.iter_with_setup(
				|| (verifier_bitmul_data.clone(), verifier_intmul_data.clone()),
				|(verifier_bitmul_data, verifier_intmul_data)| {
					// Clone the pre-computed verifier transcript for each iteration
					let mut verifier_transcript = setup_verifier_transcript.clone();
					black_box(
						verify(
							cs.clone(),
							verifier_bitmul_data,
							verifier_intmul_data,
							&mut verifier_transcript,
						)
						.unwrap(),
					)
				},
			)
		});
	}
}

criterion_group!(benches, bench_prove_and_verify);
criterion_main!(benches);
