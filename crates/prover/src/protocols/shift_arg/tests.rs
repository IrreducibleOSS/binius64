// Copyright 2025 Irreducible Inc.

use binius_field::{Field, PackedBinaryField2x128b, PackedField};
use binius_math::test_utils::random_field_buffer;

type P = PackedBinaryField2x128b;
use binius_transcript::ProverTranscript;
use binius_verifier::{config::StdChallenger, protocols::shift_arg::verify};
use itertools::izip;
use rand::{SeedableRng, rngs::StdRng};

use super::prove::{GMultilinears, MultilinearTriplet};

fn generate_random_multilinear_triplet<P: PackedField>() -> MultilinearTriplet<P> {
	let mut rng = StdRng::seed_from_u64(0);
	let log_len = 12;

	MultilinearTriplet {
		logical_left: random_field_buffer::<P>(&mut rng, log_len),
		logical_right: random_field_buffer::<P>(&mut rng, log_len),
		arithmetic_right: random_field_buffer::<P>(&mut rng, log_len),
	}
}

pub fn compute_sum<F: Field, P: PackedField<Scalar = F>>(left: &[P], right: &[P]) -> F {
	let packed_eval: P =
		izip!(left, right).fold(P::default(), |acc, (&left, &right)| acc + left * right);
	packed_eval.iter().sum()
}

#[test]
fn prove_and_verify() {
	let h_multilinear_triplet = generate_random_multilinear_triplet::<P>();
	let g_multilinears = GMultilinears {
		a: generate_random_multilinear_triplet::<P>(),
		b: generate_random_multilinear_triplet::<P>(),
		c: generate_random_multilinear_triplet::<P>(),
	};

	let mut prover_transcript = ProverTranscript::<StdChallenger>::default();

	let compute_claim = |h_triplet: &MultilinearTriplet<P>, g_triplet: &MultilinearTriplet<P>| {
		let left = compute_sum(h_triplet.logical_left.as_ref(), g_triplet.logical_left.as_ref());
		let right = compute_sum(h_triplet.logical_right.as_ref(), g_triplet.logical_right.as_ref());
		let arithmetic =
			compute_sum(h_triplet.arithmetic_right.as_ref(), g_triplet.arithmetic_right.as_ref());
		left + right + arithmetic
	};

	let a_claim = compute_claim(&h_multilinear_triplet, &g_multilinears.a);
	let b_claim = compute_claim(&h_multilinear_triplet, &g_multilinears.b);
	let c_claim = compute_claim(&h_multilinear_triplet, &g_multilinears.c);

	let phase1_output = super::prove::prove(
		g_multilinears,
		h_multilinear_triplet,
		a_claim,
		b_claim,
		c_claim,
		&mut prover_transcript,
	)
	.unwrap();

	let mut verifier_transcript = prover_transcript.into_verifier();

	let verifier_output =
		verify::verify(a_claim, b_claim, c_claim, &mut verifier_transcript).unwrap();

	assert_eq!(phase1_output, verifier_output);
}
