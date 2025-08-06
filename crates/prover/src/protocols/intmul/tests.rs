// Copyright 2025 Irreducible Inc.

use binius_field::PackedBinaryField2x128b;

use super::{prove::IntMulProver, witness::Witness};

type P = PackedBinaryField2x128b;

use binius_transcript::ProverTranscript;
use binius_verifier::{config::StdChallenger, protocols::intmul::verify};

#[test]
fn prove_and_verify() {
	use rand::{Rng, SeedableRng, rngs::StdRng};

	let mut rng = StdRng::seed_from_u64(0);

	const LOG_BITS: usize = 6;
	const LOG_EXPONENTS: usize = 5;
	const NUM_EXPONENTS: usize = 1 << LOG_EXPONENTS;
	let mut a = Vec::with_capacity(NUM_EXPONENTS);
	let mut b = Vec::with_capacity(NUM_EXPONENTS);
	let mut c_lo = Vec::with_capacity(NUM_EXPONENTS);
	let mut c_hi = Vec::with_capacity(NUM_EXPONENTS);

	for _ in 0..NUM_EXPONENTS {
		let a_i = rng.random_range(1..u64::MAX);
		let b_i = rng.random_range(1..u64::MAX);

		let full_result = (a_i as u128) * (b_i as u128);

		let c_lo_i = full_result as u64;
		let c_hi_i = (full_result >> 64) as u64;

		a.push(a_i);
		b.push(b_i);
		c_lo.push(c_lo_i);
		c_hi.push(c_hi_i);
	}

	let witness = Witness::<P, _, _>::new(LOG_BITS, &a, &b, &c_lo, &c_hi).unwrap();
	// Run prover
	let mut prover_transcript = ProverTranscript::<StdChallenger>::default();
	let mut prover = IntMulProver::new(0, &mut prover_transcript);
	let prove_output = prover.prove(witness).unwrap();

	// Run verifier
	let mut verifier_transcript = prover_transcript.into_verifier();
	let verify_output = verify(LOG_BITS, LOG_EXPONENTS, &mut verifier_transcript).unwrap();

	// Check verifier output is consistent with prover output
	assert_eq!(prove_output, verify_output);
}
