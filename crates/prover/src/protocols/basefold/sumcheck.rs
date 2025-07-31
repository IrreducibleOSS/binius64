use binius_field::{BinaryField, PackedField};
use binius_math::{FieldBuffer, line::extrapolate_line_packed};
use binius_utils::rayon::{
	iter::{IntoParallelIterator, ParallelIterator},
};
use binius_verifier::protocols::sumcheck::RoundCoeffs;

use crate::protocols::sumcheck::{Error, common::SumcheckProver};

/// A sumcheck prover for the product of two multilinear polynomials.
///
/// This struct provides a round-by-round interface to prove the sum of A(X) * B(X)
/// for multilinears A and B over all hypercube points X.
pub struct MultilinearSumcheckProver<F, P>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	multilinears: [FieldBuffer<P>; 2],
	current_round_claim: F,
	round_message: Option<RoundCoeffs<F>>,
}

impl<F, P> MultilinearSumcheckProver<F, P>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	/// Creates a new multilinear sumcheck prover.
	///
	/// ## Arguments
	///
	/// * `multilinears` - Two multilinear polynomials A and B to compute the sum of A(X) * B(X)
	/// * `overall_claim` - The claimed sum of the product over the hypercube
	/// * `log_n` - The logarithm of the number of variables (must match multilinears' log_len)
	///
	/// ## Preconditions
	///
	/// * both multilinears in the composition have the same log_len
	pub fn new(multilinears: [FieldBuffer<P>; 2], overall_claim: F, log_n: usize) -> Self {
		assert_eq!(multilinears[0].log_len(), log_n);
		assert_eq!(multilinears[1].log_len(), log_n);

		Self {
			multilinears,
			current_round_claim: overall_claim,
			round_message: None,
		}
	}
}

fn fold_low_to_high<F, P>(
	multilinear_extension: &FieldBuffer<P>,
	challenge: F,
) -> Result<FieldBuffer<P>, Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	let new_log_len = multilinear_extension.log_len() - 1;
	let out = (0..(1 << new_log_len))
	.into_par_iter()
	.map(|i| {
		let even = multilinear_extension.get(2 * i).expect("out of bounds");
		let odd = multilinear_extension.get(2 * i + 1).expect("out of bounds");
		extrapolate_line_packed(even, odd, challenge)
		})
		.collect::<Vec<_>>();

	let out = FieldBuffer::<P>::from_values(&out)?;

	Ok(out)
}

impl<F, P> SumcheckProver<F> for MultilinearSumcheckProver<F, P>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	fn n_vars(&self) -> usize {
		self.multilinears[0].log_len()
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let log_n = self.multilinears[0].log_len();
		let n = 1 << log_n;
		let n_half = n >> 1;

		let a = &self.multilinears[0];
		let b = &self.multilinears[1];

		let (g_of_zero, g_of_one, g_leading) = (0..n_half)
			.into_par_iter()
			.map(|i| {
				let a_even = a.get(2 * i).expect("a even index out of bounds");
				let a_odd = a.get(2 * i + 1).expect("a odd index out of bounds");

				let b_even = b.get(2 * i).expect("b even index out of bounds");
				let b_odd = b.get(2 * i + 1).expect("b odd index out of bounds");

				let even = a_even * b_even;
				let odd = a_odd * b_odd;
				let leading = (a_even - a_odd) * (b_even - b_odd);

				(even, odd, leading)
			})
			.reduce(
				|| (F::ZERO, F::ZERO, F::ZERO),
				|(e1, o1, l1), (e2, o2, l2)| (e1 + e2, o1 + o2, l1 + l2),
			);

		let round_coeffs =
			RoundCoeffs(vec![g_of_zero, g_of_one - g_of_zero - g_leading, g_leading]);
		self.round_message = Some(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		for m in self.multilinears.iter_mut() {
			*m = fold_low_to_high::<F, P>(m, challenge)?;
		}

		self.current_round_claim = self
			.round_message
			.as_ref()
			.expect("prover must be executed before fold")
			.evaluate(challenge);

		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		Ok(vec![self.multilinears[0].get(0)?, self.multilinears[1].get(0)?])
	}
}

#[cfg(test)]
pub mod test {
	use binius_field::{
		BinaryField, Field, Random,
		arch::{OptimalB128, packed_ghash_256::PackedBinaryGhash2x128b},
	};
	use binius_math::{multilinear::eq::eq_ind_partial_eval, test_utils::random_field_buffer};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	fn sum_composition<F, P>(a: &FieldBuffer<P>, b: &FieldBuffer<P>) -> Result<F, Error>
	where
		F: BinaryField,
		P: PackedField<Scalar = F>,
	{
		Ok((0..a.len())
			.map(|i| Ok(a.get(i)? * b.get(i)?))
			.collect::<Result<Vec<_>, Error>>()?
			.into_iter()
			.sum())
	}

	fn random_challenge<F>() -> F
	where
		F: BinaryField,
	{
		let mut rng = StdRng::from_seed([0; 32]);
		F::random(&mut rng)
	}

	pub fn sumcheck_interactive_protocol<F, P>(
		prover: &mut MultilinearSumcheckProver<F, P>,
	) -> Result<(F, Vec<F>), Error>
	where
		F: BinaryField,
		P: PackedField<Scalar = F>,
	{
		let log_n = prover.n_vars();

		let mut expected_next_round_claim = prover.current_round_claim;
		let mut sumcheck_challenges = Vec::with_capacity(log_n);

		for _ in 0..log_n {
			let round_msg = prover.execute()?;
			let round_coeffs = &round_msg[0];

			let sum_check = round_coeffs.evaluate(F::ZERO) + round_coeffs.evaluate(F::ONE);
			assert_eq!(sum_check, expected_next_round_claim, "Sumcheck constraint failed");

			let sumcheck_challenge = random_challenge();
			sumcheck_challenges.push(sumcheck_challenge);

			expected_next_round_claim = round_coeffs.evaluate(sumcheck_challenge);

			prover.fold(sumcheck_challenge)?;
		}

		Ok((expected_next_round_claim, sumcheck_challenges))
	}

	fn run_sumcheck_interactive_protocol<F, P>(
		multilinears: [FieldBuffer<P>; 2],
	) -> Result<(), Error>
	where
		F: BinaryField,
		P: PackedField<Scalar = F>,
	{
		let log_n = multilinears[0].log_len();

		let overall_claim = sum_composition::<F, P>(&multilinears[0], &multilinears[1])?;

		let mut prover =
			MultilinearSumcheckProver::<F, P>::new(multilinears.clone(), overall_claim, log_n);

		let (final_sumcheck_msg, sumcheck_challenges) = sumcheck_interactive_protocol(&mut prover)?;

		let final_eval_claims = prover.finish()?;

		let eq_tensor =
			eq_ind_partial_eval(&sumcheck_challenges.into_iter().rev().collect::<Vec<_>>());

		let eval_a = sum_composition(&multilinears[0], &eq_tensor)?;
		let eval_b = sum_composition(&multilinears[1], &eq_tensor)?;

		assert_eq!(eval_a * eval_b, final_sumcheck_msg);
		assert_eq!(final_eval_claims[0] * final_eval_claims[1], final_sumcheck_msg);

		Ok(())
	}

	#[test]
	fn test_sumcheck_low_to_high() {
		let rng = StdRng::from_seed([0; 32]);

		type P = OptimalB128;

		let log_n = 5;
		let a = random_field_buffer(rng.clone(), log_n);
		let b = random_field_buffer(rng, log_n);
		let multilinears: [FieldBuffer<P>; 2] = [a, b];
		run_sumcheck_interactive_protocol::<_, P>(multilinears).expect("sumcheck failed");
	}

	#[test]
	fn test_sumcheck_low_to_high_non_trivial_packing_width() {
		let rng = StdRng::from_seed([0; 32]);

		type P = PackedBinaryGhash2x128b;

		let log_n = 5;
		let a = random_field_buffer(rng.clone(), log_n);
		let b = random_field_buffer(rng, log_n);
		let multilinears: [FieldBuffer<P>; 2] = [a, b];
		run_sumcheck_interactive_protocol::<_, P>(multilinears).expect("sumcheck failed");
	}

	#[test]
	fn test_composition_even_odd_sum() -> Result<(), Error> {
		let mut rng = StdRng::from_seed([0; 32]);

		type F = OptimalB128;

		let log_n = 5;
		let n = 1 << log_n;

		let multilinear = random_field_buffer(rng.clone(), log_n);

		let challenges = (0..log_n).map(|_| F::random(&mut rng)).collect::<Vec<F>>();

		let eq_r: FieldBuffer<F> = eq_ind_partial_eval(&challenges.clone());

		let overall_sum = sum_composition(&multilinear, &eq_r)?;

		let mut g_of_zero = F::ZERO;
		let mut g_of_one = F::ZERO;
		for i in 0..n {
			let prod = multilinear.get(i)? * eq_r.get(i)?;
			if i.is_multiple_of(2) {
				g_of_zero += prod;
			} else {
				g_of_one += prod;
			}
		}

		assert_eq!(overall_sum, g_of_zero + g_of_one);
		Ok(())
	}
}
