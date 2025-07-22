// Copyright 2025 Irreducible Inc.

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, univariate::evaluate_univariate};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::{shift_arg::verify::Phase1Output, sumcheck::common::RoundCoeffs};
use itertools::izip;

use super::error::Error;
use crate::protocols::sumcheck::{
	bivariate_product::BivariateProductSumcheckProver, common::SumcheckProver,
};

// every field buffer is of log_len 12
#[derive(Debug, Clone)]
pub struct MultilinearTriplet<P: PackedField> {
	pub logical_left: FieldBuffer<P>,
	pub logical_right: FieldBuffer<P>,
	pub arithmetic_right: FieldBuffer<P>,
}

#[derive(Debug, Clone)]
pub struct GMultilinears<P: PackedField> {
	pub a: MultilinearTriplet<P>,
	pub b: MultilinearTriplet<P>,
	pub c: MultilinearTriplet<P>,
}

fn compute_g_multilinear_tripet<F: Field, P: PackedField<Scalar = F>>(
	g_multilinears: GMultilinears<P>,
	lambda: F,
) -> MultilinearTriplet<P> {
	let packed_lambda = P::broadcast(lambda);
	let packed_lambda_square = P::broadcast(lambda.square());

	let compute_batched_g_multilinear = |mut multilinear_a: FieldBuffer<P>,
	                                     multilinear_b: FieldBuffer<P>,
	                                     multilinear_c: FieldBuffer<P>|
	 -> FieldBuffer<P> {
		for (a, b, c) in
			izip!(multilinear_a.as_mut(), multilinear_b.as_ref(), multilinear_c.as_ref())
		{
			*a += packed_lambda * *b + packed_lambda_square * *c;
		}

		multilinear_a
	};

	MultilinearTriplet {
		logical_left: compute_batched_g_multilinear(
			g_multilinears.a.logical_left,
			g_multilinears.b.logical_left,
			g_multilinears.c.logical_left,
		),
		logical_right: compute_batched_g_multilinear(
			g_multilinears.a.logical_right,
			g_multilinears.b.logical_right,
			g_multilinears.c.logical_right,
		),
		arithmetic_right: compute_batched_g_multilinear(
			g_multilinears.a.arithmetic_right,
			g_multilinears.b.arithmetic_right,
			g_multilinears.c.arithmetic_right,
		),
	}
}

fn check_multilnear_triplet_lengths<P: PackedField>(triplet: &MultilinearTriplet<P>) {
	assert_eq!(triplet.logical_left.log_len(), 12);
	assert_eq!(triplet.logical_right.log_len(), 12);
	assert_eq!(triplet.arithmetic_right.log_len(), 12);
}

fn compute_bivariate_product_sum<F: Field, P: PackedField<Scalar = F>>(
	left: &[P],
	right: &[P],
) -> F {
	izip!(left, right)
		.fold(P::default(), |acc, (&left, &right)| acc + left * right)
		.iter()
		.sum()
}

/// Reduces the three claims at the start of the shift reduction
/// to a Phase1Output by proving the sumcheck in the first phase.
pub fn prove<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	g_multilinears: GMultilinears<P>,
	h_multilinear_triplet: MultilinearTriplet<P>,
	a_claim: F,
	b_claim: F,
	c_claim: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let lambda = transcript.sample();
	let starting_sum = evaluate_univariate(&[a_claim, b_claim, c_claim], lambda);

	let g_multilinear_triplet = compute_g_multilinear_tripet(g_multilinears, lambda);

	check_multilnear_triplet_lengths(&g_multilinear_triplet);
	check_multilnear_triplet_lengths(&h_multilinear_triplet);

	fn make_prover<P: PackedField>(
		left: FieldBuffer<P>,
		right: FieldBuffer<P>,
		sum: P::Scalar,
	) -> Result<BivariateProductSumcheckProver<P>, Error> {
		BivariateProductSumcheckProver::new([left, right], sum).map_err(Error::from_sumcheck_new)
	}

	// logical left
	let logical_left_sum = compute_bivariate_product_sum(
		g_multilinear_triplet.logical_left.as_ref(),
		h_multilinear_triplet.logical_left.as_ref(),
	);

	let logical_left_prover = make_prover(
		g_multilinear_triplet.logical_left,
		h_multilinear_triplet.logical_left,
		logical_left_sum,
	)?;

	// logical right
	let logical_right_sum = compute_bivariate_product_sum(
		g_multilinear_triplet.logical_right.as_ref(),
		h_multilinear_triplet.logical_right.as_ref(),
	);

	let logical_right_prover = make_prover(
		g_multilinear_triplet.logical_right,
		h_multilinear_triplet.logical_right,
		logical_right_sum,
	)?;

	// arithmetic right
	let arithmetic_right_sum = starting_sum - logical_left_sum - logical_right_sum;

	let arithmetic_right_prover = make_prover(
		g_multilinear_triplet.arithmetic_right,
		h_multilinear_triplet.arithmetic_right,
		arithmetic_right_sum,
	)?;

	let mut provers = vec![
		logical_left_prover,
		logical_right_prover,
		arithmetic_right_prover,
	];

	let n_vars = 12;

	let mut challenges = Vec::with_capacity(n_vars);

	for _ in 0..n_vars {
		let mut all_round_coeffs = Vec::new();

		for prover in &mut provers {
			all_round_coeffs.extend(prover.execute().map_err(Error::from_sumcheck_execute)?);
		}

		let summed_round_coeffs = all_round_coeffs
			.into_iter()
			.rfold(RoundCoeffs::default(), |acc, coeffs| acc + &coeffs);

		let round_proof = summed_round_coeffs.truncate();

		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		let challenge = transcript.sample();
		challenges.push(challenge);

		for prover in &mut provers {
			prover.fold(challenge).map_err(Error::from_sumcheck_fold)?;
		}
	}

	challenges.reverse();

	let s_challenges = challenges.split_off(6);
	let j_challenges = challenges;

	let multilinear_evals: Vec<Vec<F>> = provers
		.into_iter()
		.map(|prover| prover.finish().map_err(Error::from_sumcheck_finish))
		.collect::<Result<Vec<_>, _>>()?;

	let mut writer = transcript.message();

	let claim = multilinear_evals
		.into_iter()
		.map(|prover_evals: Vec<F>| {
			assert_eq!(prover_evals.len(), 2);
			let h_eval = prover_evals[0];
			let g_eval = prover_evals[1];

			writer.write_scalar_slice(&[h_eval, g_eval]);

			h_eval * g_eval
		})
		.sum();

	Ok(Phase1Output {
		lambda,
		j_challenges,
		s_challenges,
		claim,
	})
}
