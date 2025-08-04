// Copyright 2023-2025 Irreducible Inc.

use std::cmp::max;

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, multilinear::fold::fold_highest_var_inplace};
use binius_utils::rayon::prelude::*;
use binius_verifier::protocols::sumcheck::RoundCoeffs;
use itertools::{Itertools, izip};

use super::{common::SumcheckProver, error::Error, gruen34::Gruen34, round_evals::RoundEvals2};
use crate::protocols::sumcheck::common::MleCheckProver;

/// Multiple claim version of `BivariateProductMlecheckProver` that can prove mlechecks
/// that share the evaluation point. This allows deduplicating folding and evaluation work.
pub struct AffineInverseMLECheckProver<P: PackedField> {
	x: FieldBuffer<P>,
    y: FieldBuffer<P>,
	last_coeffs_or_sums: RoundCoeffsOrSums<P::Scalar>,
	gruen34: Gruen34<P>,
}

impl<F: Field, P: PackedField<Scalar = F>> AffineInverseMLECheckProver<P> {
	/// Constructs a prover, given the multilinear polynomial evaluations (in pairs) and
	/// evaluation claims on the shared evaluation point.
	pub fn new(
		x: FieldBuffer<P>,
		eval_point: &[F],
		eval_claims: &[F],// for our use case these should just be zeros
	) -> Result<Self, Error> {
		let n_vars = eval_point.len();

		if multilinears
			.iter()
			.flatten()
			.any(|multilinear| multilinear.log_len() != n_vars)
		{
			return Err(Error::MultilinearSizeMismatch);
		}

		if multilinears.len() != eval_claims.len() {
			return Err(Error::EvalClaimsNumberMismatch);
		}

		let multilinears = multilinears.into_iter().flatten().collect_vec();
		let last_coeffs_or_sums = RoundCoeffsOrSums::Sums(eval_claims.to_vec());

		let gruen34 = Gruen34::new(eval_point);

		Ok(Self {
			multilinears,
			last_coeffs_or_sums,
			gruen34,
		})
	}
}

impl<F, P> SumcheckProver<F> for AffineInverseMLECheckProver<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	fn n_vars(&self) -> usize {
		self.gruen34.n_vars_remaining()
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let RoundCoeffsOrSums::Sums(sums) = &self.last_coeffs_or_sums else {
			return Err(Error::ExpectedFold);
		};

		assert!(self.n_vars() > 0);

		// Perform chunked summation: for every row, evaluate all compositions and add up
		// results to an array of round evals accumulators. Alternative would be to sum each
		// composition on its own pass, but that would require reading the entirety of eq field
		// buffer on each pass, which will evict the latter from the cache. By doing chunked
		// compute, we reasonably hope that eq chunk always stays in L1 cache.
		const MAX_CHUNK_VARS: usize = 12;
		let chunk_vars = max(MAX_CHUNK_VARS, P::LOG_WIDTH).min(self.n_vars() - 1);

		let packed_prime_evals = (0..1 << (self.n_vars() - 1 - chunk_vars))
			.into_par_iter()
			.try_fold(
				|| vec![RoundEvals2::default(); sums.len()],
				|mut packed_prime_evals: Vec<RoundEvals2<P>>, chunk_index| -> Result<_, Error> {
					let eq_chunk = self.gruen34.eq_expansion().chunk(chunk_vars, chunk_index)?;

					for (round_evals, (evals_a, evals_b)) in
						izip!(&mut packed_prime_evals, [self.x,self.y].iter().tuples())
					{
						let (evals_a_0, evals_a_1) = evals_a.split_half()?;
						let (evals_b_0, evals_b_1) = evals_b.split_half()?;

						let evals_a_0_chunk = evals_a_0.chunk(chunk_vars, chunk_index)?;
						let evals_b_0_chunk = evals_b_0.chunk(chunk_vars, chunk_index)?;
						let evals_a_1_chunk = evals_a_1.chunk(chunk_vars, chunk_index)?;
						let evals_b_1_chunk = evals_b_1.chunk(chunk_vars, chunk_index)?;

						for (&eq_i, &evals_a_0_i, &evals_b_0_i, &evals_a_1_i, &evals_b_1_i) in izip!(
							eq_chunk.as_ref(),
							evals_a_0_chunk.as_ref(),
							evals_b_0_chunk.as_ref(),
							evals_a_1_chunk.as_ref(),
							evals_b_1_chunk.as_ref()
						) {
							let evals_a_inf_i = evals_a_0_i + evals_a_1_i;
							let evals_b_inf_i = evals_b_0_i + evals_b_1_i;

							round_evals.y_1 += eq_i * evals_a_1_i * evals_b_1_i;
							round_evals.y_inf += eq_i * evals_a_inf_i * evals_b_inf_i;
						}
					}

					Ok(packed_prime_evals)
				},
			)
			.try_reduce(
				|| vec![RoundEvals2::default(); sums.len()],
				|lhs, rhs| Ok(izip!(lhs, rhs).map(|(l, r)| l + &r).collect()),
			)?;

		let alpha = self.gruen34.next_coordinate();
		let round_coeffs = izip!(sums, packed_prime_evals)
			.map(|(&sum, packed_evals)| {
				let round_evals = packed_evals.sum_scalars(self.n_vars());
				round_evals.interpolate_eq(sum, alpha)
			})
			.collect::<Vec<_>>();

		self.last_coeffs_or_sums = RoundCoeffsOrSums::Coeffs(round_coeffs.clone());
		Ok(round_coeffs)
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		let RoundCoeffsOrSums::Coeffs(prime_coeffs) = &self.last_coeffs_or_sums else {
			return Err(Error::ExpectedExecute);
		};

		assert!(self.n_vars() > 0);

		let sums = prime_coeffs
			.iter()
			.map(|coeffs| coeffs.evaluate(challenge))
			.collect();

		for multilinear in &mut [self.x, self.y] {
			fold_highest_var_inplace(multilinear, challenge)?;
		}

		self.gruen34.fold(challenge)?;
		self.last_coeffs_or_sums = RoundCoeffsOrSums::Sums(sums);
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		if self.n_vars() > 0 {
			let error = match self.last_coeffs_or_sums {
				RoundCoeffsOrSums::Coeffs(_) => Error::ExpectedFold,
				RoundCoeffsOrSums::Sums(_) => Error::ExpectedExecute,
			};

			return Err(error);
		}

		let multilinear_evals = self
			.multilinears
			.into_iter()
			.map(|multilinear| multilinear.get(0).expect("multilinear.len() == 1"))
			.collect();

		Ok(multilinear_evals)
	}
}

impl<F, P> MleCheckProver<F> for AffineInverseMLECheckProver<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	fn eval_point(&self) -> &[F] {
		self.gruen34.eval_point()
	}
}

enum RoundCoeffsOrSums<F: Field> {
	Coeffs(Vec<RoundCoeffs<F>>),
	Sums(Vec<F>),
}
#[cfg(test)]
mod tests {
	use binius_field::arch::{OptimalB128, OptimalPackedB128};
	use binius_math::{
		multilinear::{eq::eq_ind, evaluate::evaluate},
		test_utils::{random_field_buffer, random_scalars},
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		config::StdChallenger,
		protocols::{mlecheck, sumcheck::verify},
	};
	use itertools::{self, Itertools};
	use rand::{SeedableRng, prelude::StdRng};

	use super::*;
	use crate::protocols::sumcheck::{
		MleToSumCheckDecorator, prove::prove_single, prove_single_mlecheck,
	};

	fn test_mlecheck_prove_verify<F, P>(
		prover: impl MleCheckProver<F>,
		eval_claim: F,
		eval_point: &[F],
		multilinear_a: FieldBuffer<P>,
		multilinear_b: FieldBuffer<P>,
	) where
		F: Field,
		P: PackedField<Scalar = F>,
	{
		// Run the proving protocol
		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let output = prove_single_mlecheck(prover, &mut prover_transcript).unwrap();

		// Write the multilinear evaluations to the transcript
		prover_transcript
			.message()
			.write_slice(&output.multilinear_evals);

		// Convert to verifier transcript and run verification
		let mut verifier_transcript = prover_transcript.into_verifier();
		let sumcheck_output = mlecheck::verify::<F, _>(
			eval_point,
			2, // degree 2 for bivariate product
			eval_claim,
			&mut verifier_transcript,
		)
		.unwrap();

		let mut reduced_eval_point = sumcheck_output.challenges.clone();
		reduced_eval_point.reverse();

		// Read the multilinear evaluations from the transcript
		let multilinear_evals: Vec<F> = verifier_transcript.message().read_vec(2).unwrap();

		// Check that the product of the evaluations equals the reduced evaluation
		assert_eq!(
			multilinear_evals[0] * multilinear_evals[1],
			sumcheck_output.eval,
			"Product of multilinear evaluations should equal the reduced evaluation"
		);

		// Check that the original multilinears evaluate to the claimed values at the challenge
		// point The prover binds variables from high to low, but evaluate expects them from low
		// to high
		let eval_a = evaluate(&multilinear_a, &reduced_eval_point).unwrap();
		let eval_b = evaluate(&multilinear_b, &reduced_eval_point).unwrap();

		assert_eq!(
			eval_a, multilinear_evals[0],
			"Multilinear A should evaluate to the first claimed evaluation"
		);
		assert_eq!(
			eval_b, multilinear_evals[1],
			"Multilinear B should evaluate to the second claimed evaluation"
		);

		// Also verify the challenges match what the prover saw
		assert_eq!(
			output.challenges, sumcheck_output.challenges,
			"Prover and verifier challenges should match"
		);
	}

	fn test_wrapped_sumcheck_prove_verify<F, P>(
		mlecheck_prover: impl MleCheckProver<F>,
		eval_claim: F,
		eval_point: &[F],
		multilinear_a: FieldBuffer<P>,
		multilinear_b: FieldBuffer<P>,
	) where
		F: Field,
		P: PackedField<Scalar = F>,
	{
		let n_vars = mlecheck_prover.n_vars();
		let prover = MleToSumCheckDecorator::new(mlecheck_prover);

		// Run the proving protocol
		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		let output = prove_single(prover, &mut prover_transcript).unwrap();

		// Write the multilinear evaluations to the transcript
		prover_transcript
			.message()
			.write_slice(&output.multilinear_evals);

		// Convert to verifier transcript and run verification
		let mut verifier_transcript = prover_transcript.into_verifier();
		let sumcheck_output = verify::<F, _>(
			n_vars,
			3, // degree 3 for trivariate product (bivariate by equality indicator)
			eval_claim,
			&mut verifier_transcript,
		)
		.unwrap();

		// The prover binds variables from high to low, but evaluate expects them from low
		// to high
		let mut reduced_eval_point = sumcheck_output.challenges.clone();
		reduced_eval_point.reverse();

		// Read the multilinear evaluations from the transcript
		let multilinear_evals: Vec<F> = verifier_transcript.message().read_vec(2).unwrap();

		// Evaluate the equality indicator
		let eq_ind_eval = eq_ind(eval_point, &reduced_eval_point);

		// Check that the product of the evaluations equals the reduced evaluation
		assert_eq!(
			multilinear_evals[0] * multilinear_evals[1] * eq_ind_eval,
			sumcheck_output.eval,
			"Product of multilinear evaluations should equal the reduced evaluation"
		);

		// Check that the original multilinears evaluate to the claimed values at the challenge
		// point
		let eval_a = evaluate(&multilinear_a, &reduced_eval_point).unwrap();
		let eval_b = evaluate(&multilinear_b, &reduced_eval_point).unwrap();

		assert_eq!(
			eval_a, multilinear_evals[0],
			"Multilinear A should evaluate to the first claimed evaluation"
		);
		assert_eq!(
			eval_b, multilinear_evals[1],
			"Multilinear B should evaluate to the second claimed evaluation"
		);

		// Also verify the challenges match what the prover saw
		assert_eq!(
			output.challenges, sumcheck_output.challenges,
			"Prover and verifier challenges should match"
		);
	}

	#[test]
	fn test_bivariate_product_mlecheck() {
		type F = OptimalB128;
		type P = OptimalPackedB128;

		let n_vars = 8;
		let mut rng = StdRng::seed_from_u64(0);

		// Generate two random multilinear polynomials
		let multilinear_a = random_field_buffer::<P>(&mut rng, n_vars);
		let multilinear_b = random_field_buffer::<P>(&mut rng, n_vars);

		// Compute product multilinear
		let product = itertools::zip_eq(multilinear_a.as_ref(), multilinear_b.as_ref())
			.map(|(&l, &r)| l * r)
			.collect_vec();
		let product_buffer = FieldBuffer::new(n_vars, product).unwrap();

		let eval_point = random_scalars::<F>(&mut rng, n_vars);
		let eval_claim = evaluate(&product_buffer, &eval_point).unwrap();

		// Create the prover
		let mlecheck_prover = BivariateProductMlecheckProver::new(
			[multilinear_a.clone(), multilinear_b.clone()],
			&eval_point,
			eval_claim,
		)
		.unwrap();

		test_mlecheck_prove_verify(
			mlecheck_prover.clone(),
			eval_claim,
			&eval_point,
			multilinear_a.clone(),
			multilinear_b.clone(),
		);

		test_wrapped_sumcheck_prove_verify(
			mlecheck_prover.clone(),
			eval_claim,
			&eval_point,
			multilinear_a.clone(),
			multilinear_b.clone(),
		);
	}
}
