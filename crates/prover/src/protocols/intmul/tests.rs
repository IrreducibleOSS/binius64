// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField128b, PackedBinaryField2x128b, PackedField};

use super::{prove::IntMulProver, witness::Witness};

type F = BinaryField128b;
type P = PackedBinaryField2x128b;

use binius_math::{FieldBuffer, multilinear::evaluate::evaluate};
use binius_transcript::ProverTranscript;
use binius_verifier::{config::StdChallenger, protocols::intmul::verify};

pub fn make_bit_multilinear<P: PackedField>(i: usize, exp: &[u64]) -> FieldBuffer<P> {
	let packed_elements = exp
		.iter()
		.map(|exp| {
			if exp & (1 << i) == 0 {
				P::Scalar::zero()
			} else {
				P::Scalar::one()
			}
		})
		.collect::<Vec<_>>();
	FieldBuffer::from_values(&packed_elements).expect("input length is power of 2")
}

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
	// run prover
	let mut prover_transcript = ProverTranscript::<StdChallenger>::default();
	let mut prover = IntMulProver::new(0, &mut prover_transcript);
	let prove_output = prover.prove(witness).unwrap();

	// check prover output is consistent with input
	let check_evals = |exponents: &[u64], given_evals: &[F]| {
		for i in 0..64 {
			let field_buffer = make_bit_multilinear::<P>(i, exponents);
			let expected_eval = evaluate(&field_buffer, &prove_output.eval_point).unwrap();
			assert_eq!(expected_eval, given_evals[i]);
		}
	};
	check_evals(&a, &prove_output.a_exponent_evals);
	check_evals(&b, &prove_output.b_exponent_evals);
	check_evals(&c_lo, &prove_output.c_lo_exponent_evals);
	check_evals(&c_hi, &prove_output.c_hi_exponent_evals);

	// run verifier
	let mut verifier_transcript = prover_transcript.into_verifier();
	let verify_output = verify::verify(LOG_BITS, LOG_EXPONENTS, &mut verifier_transcript).unwrap();

	// check verifier output is consistent with prover output
	assert_eq!(prove_output, verify_output);
}
