use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, univariate::evaluate_univariate};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::{shift_arg::verify::Phase1Output, sumcheck::common::RoundCoeffs};
use itertools::{Itertools, izip};

use super::error::Error;
use crate::protocols::sumcheck::{
	bivariate_product_sum::BivariateProductProver, common::SumcheckProver,
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

pub fn prove<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	g_multilinears: GMultilinears<P>,
	h_multilinear_triplet: MultilinearTriplet<P>,
	a_claim: F,
	b_claim: F,
	c_claim: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let lambda = transcript.sample();

	let g_multilinear_triplet = compute_g_multilinear_tripet(g_multilinears, lambda);
	let claim = evaluate_univariate(&[a_claim, b_claim, c_claim], lambda);

	check_multilnear_triplet_lengths(&g_multilinear_triplet);
	check_multilnear_triplet_lengths(&h_multilinear_triplet);

	let n_vars = 12;

	let multilinear_pairs = vec![
		(g_multilinear_triplet.logical_left, h_multilinear_triplet.logical_left),
		(g_multilinear_triplet.logical_right, h_multilinear_triplet.logical_right),
		(g_multilinear_triplet.arithmetic_right, h_multilinear_triplet.arithmetic_right),
	];

	let mut prover = BivariateProductProver::new(n_vars, multilinear_pairs, claim)
		.map_err(Error::from_sumcheck_new)?;

	let mut challenges = Vec::with_capacity(n_vars);
	for _ in 0..n_vars {
		let round_coeffs_vec = prover.execute().map_err(Error::from_sumcheck_execute)?;

		let summed_round_coeffs: RoundCoeffs<F> = round_coeffs_vec
			.into_iter()
			.rfold(RoundCoeffs::default(), |acc, coeffs| acc + &coeffs);

		let round_proof = summed_round_coeffs.truncate();

		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		let challenge = transcript.sample();
		challenges.push(challenge);

		prover.fold(challenge).map_err(Error::from_sumcheck_fold)?;
	}

	challenges.reverse();

	let s_challenges = challenges.split_off(6);
	let j_challenges = challenges;

	let evals: Vec<F> = prover.finish().map_err(Error::from_sumcheck_finish)?;

	let mut writer = transcript.message();

	let claim = evals
		.into_iter()
		.tuples()
		.map(|(h_eval, g_eval): (F, F)| {
			// for now to check consistency with verifier, write multilinear evals to transcript
			// when phase 2 is implemented this will be removed
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
