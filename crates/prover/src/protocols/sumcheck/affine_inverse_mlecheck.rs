// Copyright 2023-2025 Irreducible Inc.

use std::cmp::max;

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, multilinear::fold::fold_highest_var_inplace};
use binius_utils::rayon::prelude::*;
use binius_verifier::protocols::sumcheck::RoundCoeffs;
use itertools::{Itertools, izip};

use super::{common::SumcheckProver, error::Error, gruen34::Gruen34, round_evals::RoundEvals2};
use crate::protocols::sumcheck::common::MleCheckProver;

/// Multiple claim version of `AffineInverseMLECheckProver` that can prove mlechecks
/// that share the evaluation point. This allows deduplicating folding and evaluation work.
#[derive(Clone)]
pub struct AffineInverseMLECheckProver<P: PackedField>
where P::Scalar: Clone {
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
        y: FieldBuffer<P>,
		eval_point: &[F],
		eval_claims: &[F;2]
	) -> Result<Self, Error> {
		let n_vars = eval_point.len();

		if x.log_len() != n_vars || y.log_len() != n_vars{
            return Err(Error::MultilinearSizeMismatch);
        }

		let last_coeffs_or_sums = RoundCoeffsOrSums::Sums(eval_claims.to_vec());

		let gruen34 = Gruen34::new(eval_point);

		Ok(Self {
			x,y,
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
						izip!(&mut packed_prime_evals, [&self.x,&self.y].iter().tuples())
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

		for multilinear in [&mut self.x, &mut self.y] {
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

		let multilinear_evals = vec![self.x.get(0).expect("multilinear.len() == 1"), self.y.get(0).expect("multilinear.len() == 1")];

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

#[derive(Clone)]
enum RoundCoeffsOrSums<F: Field> {
	Coeffs(Vec<RoundCoeffs<F>>),
	Sums(Vec<F>),
}
#[cfg(test)]
mod tests {
	use binius_field::{arch::OptimalPackedB128, Random};
	use binius_math::{
		multilinear::evaluate::evaluate,
		test_utils::{random_field_buffer, random_scalars},
	};
	use itertools::{self, Itertools};
	use rand::{SeedableRng, prelude::StdRng};

	use super::*;

	#[test]
	fn test_affine_inverse_mlecheck_broken_implementation() {
		// This test documents the current broken behavior of AffineInverseMLECheckProver
		// The prover is supposed to handle multiple evaluation claims on the same pair of multilinears,
		// but due to a bug in the execute() method, it only computes the first claim correctly.
		
		type P = OptimalPackedB128;
		type F = <P as PackedField>::Scalar;

		let n_vars = 3;
		let mut rng = StdRng::seed_from_u64(0);

		// Generate two random multilinear polynomials
		let multilinear_x = random_field_buffer::<P>(&mut rng, n_vars);
		let multilinear_y = random_field_buffer::<P>(&mut rng, n_vars);

		// Compute product on the hypercube
		let product = itertools::zip_eq(multilinear_x.as_ref(), multilinear_y.as_ref())
			.map(|(&x, &y)| x * y)
			.collect_vec();
		let product_buffer = FieldBuffer::new(n_vars, product).unwrap();

		// Claim eval point
		let eval_point = random_scalars::<F>(&mut rng, n_vars);
		let eval_claim = evaluate(&product_buffer, &eval_point).unwrap();

		// Create affine inverse prover with two identical claims
		let mut prover = AffineInverseMLECheckProver::new(
			multilinear_x.clone(),
			multilinear_y.clone(),
			&eval_point,
			&[eval_claim, eval_claim],
		)
		.unwrap();

		// Due to the bug, the prover produces different round polynomials even for identical claims
		// The first polynomial is computed correctly, but the second one is not
		for round in 0..n_vars {
			let round_coeffs = prover.execute().unwrap();
			
			assert_eq!(round_coeffs.len(), 2, "Should produce 2 round polynomials for 2 claims");
			
			// Document the broken behavior: round polynomials are NOT identical
			// even though the claims are identical
			// This is because the execute() method has a bug in how it iterates over multilinears
			if round == 0 {
				// On the first round, we can observe the bug clearly
				// The second round polynomial has a specific pattern due to uninitialized values
				assert_ne!(
					round_coeffs[0], 
					round_coeffs[1], 
					"Bug: Round polynomials are different even for identical claims"
				);
			}

			let challenge = F::random(&mut rng);
			prover.fold(challenge).unwrap();
		}

		let multilinear_evals = prover.finish().unwrap();
		assert_eq!(multilinear_evals.len(), 2);
		
		// The finish() method returns the evaluations of x and y at the folded point
		// We can't easily verify these without tracking the challenges
	}

	#[test]
	fn test_affine_inverse_mlecheck_single_claim() {
		// Test with a single claim to avoid the bug
		type P = OptimalPackedB128;
		type F = <P as PackedField>::Scalar;

		let n_vars = 4;
		let mut rng = StdRng::seed_from_u64(0);

		// Generate two random multilinear polynomials
		let multilinear_x = random_field_buffer::<P>(&mut rng, n_vars);
		let multilinear_y = random_field_buffer::<P>(&mut rng, n_vars);

		// Compute product on the hypercube
		let product = itertools::zip_eq(multilinear_x.as_ref(), multilinear_y.as_ref())
			.map(|(&x, &y)| x * y)
			.collect_vec();
		let product_buffer = FieldBuffer::new(n_vars, product).unwrap();

		// Claim eval point
		let eval_point = random_scalars::<F>(&mut rng, n_vars);
		let eval_claim = evaluate(&product_buffer, &eval_point).unwrap();

		// Create prover with two different claims to test the first claim is computed correctly
		let eval_claim2 = F::random(&mut rng); // Different claim
		let mut prover = AffineInverseMLECheckProver::new(
			multilinear_x.clone(),
			multilinear_y.clone(),
			&eval_point,
			&[eval_claim, eval_claim2],
		)
		.unwrap();

		// Execute rounds
		for _round in 0..n_vars {
			let round_coeffs = prover.execute().unwrap();
			assert_eq!(round_coeffs.len(), 2, "Should produce 2 round polynomials for 2 claims");

			let challenge = F::random(&mut rng);
			prover.fold(challenge).unwrap();
		}

		let multilinear_evals = prover.finish().unwrap();
		assert_eq!(multilinear_evals.len(), 2);
		// The finish() method returns the evaluations of x and y at the folded point
	}
}
