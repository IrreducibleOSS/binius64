// Copyright 2023-2025 Irreducible Inc.

use std::array;

use binius_field::{Field, PackedField};
use binius_math::{FieldBuffer, multilinear::fold::fold_highest_var_inplace};
use binius_utils::rayon::prelude::*;
use binius_verifier::protocols::sumcheck::RoundCoeffs;

use super::{common::SumcheckProver, error::Error, gruen34::Gruen34};
use crate::protocols::sumcheck::common::MleCheckProver;

/// A [`SumcheckProver`] implementation that reduces an evaluation claim on a multilinear extension
/// of the composition $A^2 \cdot B - A$ to evaluation claims on the constituent multilinears.
/// We call such reductions Mlechecks.
///
/// ## Mathematical Definition
/// * $n \in \mathbb{N}$ - number of variables in multilinear polynomials
/// * $A, B \in \mathbb{F}[x]$, $x = (x_1, \ldots, x_n)$ - input multilinears
/// * $(A^2B - A)(x) = y$ - evaluation claim on the composition MLE
///
/// The claim is equivalent to $P(x) = \sum_{v \in \{0,1\}^n} \widetilde{eq}(v, x) (A(v)^2 B(v) -
/// A(v)) = y$, and the reduction can be achieved by sumchecking this degree-4 composition. The
/// paper [Gruen24], however, describes a way to partition the $\widetilde{eq}(v, x)$ into three
/// parts in round $j \in 1, \ldots, n$ during specialization of variable $v_{n-j+1}$, with $j-1$
/// challenges $\alpha_i$ already sampled:
///
/// $$ \widetilde{eq}(x_{n-j+2}, \ldots, x_n; \alpha_{j-1}, \ldots, \alpha_{1}) \tag{1} $$
/// $$ \widetilde{eq}(x_{n-j+1}; v_{n-j+1}) \tag{2} $$
/// $$ \widetilde{eq}(x_1, \ldots, x_{n-j}; v_1, \ldots, v_{n-j}) \tag{3} $$
///
/// The following holds:
/// * (1) is a constant that can be incrementally updated in O(1) time,
/// * (2) is a linear polynomial that is easy to compute in monomial form specialized to either
///   variable
/// * (3) is an equality indicator over the claim point suffix
///
/// These observations allow us to instead sumcheck:
/// $$
/// P'(x) = \sum_{v \in \{0,1\}^n} \widetilde{eq}(x_1, \ldots, x_{n-j}; v_1, \ldots, v_{n-j})
/// (A(v)^2 B(v) - A(v)) $$
///
/// Which is simpler because:
/// * $P'(x)$ is degree-3 in $j$-th variable (since $A^2 \cdot B - A$ has degree 3), requiring one
///   less evaluation point
/// * Equality indicator expansion does not depend on $j$-th variable and thus doesn't need to be
///   interpolated
///
/// After computing the round polynomial for $P'(x)$ in monomial form, one can simply multiply by
/// (2) and (1) in polynomial form. For more details, see [`Gruen34`]('gruen34::Gruen34') struct and
/// [Gruen24] Section 3.4.
///
/// Note 1: as evident from the definition, this prover binds variables in high-to-low index order.
///
/// Note 2: evaluation points are 0 (implicit), 1 and Karatsuba infinity.
///
/// # Invariants
///
/// - The length of both multilinears is always equal.
///
/// [Gruen24]: <https://eprint.iacr.org/2024/108>
#[derive(Debug, Clone)]
pub struct XSquaredYMinusXMlecheckProver<P: PackedField> {
	multilinears: [FieldBuffer<P>; 2],
	last_coeffs_or_eval: RoundCoeffsOrEval<P::Scalar>,
	gruen34: Gruen34<P>,
}

impl<F: Field, P: PackedField<Scalar = F>> XSquaredYMinusXMlecheckProver<P> {
	/// Constructs a prover, given the multilinear polynomial evaluations and the evaluation
	/// claim on the multilinear extension of their composition $A^2 \cdot B - A$.
	pub fn new(
		multilinears: [FieldBuffer<P>; 2],
		eval_point: &[F],
		eval_claim: F,
	) -> Result<Self, Error> {
		if multilinears[0].log_len() != multilinears[1].log_len() {
			return Err(Error::MultilinearSizeMismatch);
		}

		if multilinears[0].log_len() != eval_point.len() {
			return Err(Error::EvalPointLengthMismatch);
		}

		let last_coeffs_or_sum = RoundCoeffsOrEval::Eval(eval_claim);

		let gruen34 = Gruen34::new(eval_point);

		Ok(Self {
			multilinears,
			last_coeffs_or_eval: last_coeffs_or_sum,
			gruen34,
		})
	}
}

impl<F, P> SumcheckProver<F> for XSquaredYMinusXMlecheckProver<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	fn n_vars(&self) -> usize {
		self.gruen34.n_vars_remaining()
	}

	fn execute(&mut self) -> Result<Vec<RoundCoeffs<F>>, Error> {
		let RoundCoeffsOrEval::Eval(last_eval) = &self.last_coeffs_or_eval else {
			return Err(Error::ExpectedFold);
		};

		// Multilinear inputs are the same length by invariant
		debug_assert_eq!(self.multilinears[0].len(), self.multilinears[1].len());

		let n_vars_remaining = self.n_vars();
		assert!(n_vars_remaining > 0);

		// For P' the eq expansion does not depend on the currently specialized variable and
		// thus doesn't need to be interpolated.
		let eq_expansion = self.gruen34.eq_expansion();

		let (evals_a_0, evals_a_1) = self.multilinears[0].split_half()?;
		let (evals_b_0, evals_b_1) = self.multilinears[1].split_half()?;

		// Compute R(x) by computing its monomial basis coefficients directly
		let all_coeffs_but_lowest = (
			eq_expansion.as_ref(),
			evals_a_0.as_ref(),
			evals_a_1.as_ref(),
			evals_b_0.as_ref(),
			evals_b_1.as_ref(),
		)
			.into_par_iter()
			.map(|(&eq_i, &evals_a_0_i, &evals_a_1_i, &evals_b_0_i, &evals_b_1_i)| {
				// Note, the univariate polynomial at this vertex is just (a_1 * x + a_0)^2 *
				// (b_1 * x + b_0) - (a_1 * x + a_0) = (a_1^2 * x^2 + a_0^2) * (b_1 * x + b_0) -
				// (a_1 * x + a_0) = a_1^2 * b_1 * x^3 + a_1^2 * b_0 * x^2 + (a_0^2 * b_1 +
				// a_1) *x + (a_0^2 * b_0) + a_0
				let a_deg0 = evals_a_0_i;
				let b_deg0 = evals_b_0_i;

				let a_deg1 = evals_a_0_i + evals_a_1_i;
				let b_deg1 = evals_b_0_i + evals_b_1_i;

				let a_deg0_sq = a_deg0.square();
				let a_deg1_sq = a_deg1.square();

				[
					eq_i * (a_deg0_sq * b_deg1 + a_deg1),
					eq_i * (a_deg1_sq * b_deg0),
					eq_i * (a_deg1_sq * b_deg1),
				]
			})
			.reduce(|| [P::zero(); 3], |lhs, rhs| array::from_fn(|i| lhs[i] + rhs[i]));

		let all_coeffs_but_lowest: [F; 3] =
			array::from_fn(|i| all_coeffs_but_lowest[i].iter().sum());

		let alpha: F = self.gruen34.next_coordinate();
		let lowest_coeff: F = *last_eval
			+ (alpha
				* (all_coeffs_but_lowest[0] + all_coeffs_but_lowest[1] + all_coeffs_but_lowest[2]));
		let mut round_coeffs = vec![lowest_coeff];
		round_coeffs.extend_from_slice(&all_coeffs_but_lowest);

		let round_coeffs = RoundCoeffs(round_coeffs);

		self.last_coeffs_or_eval = RoundCoeffsOrEval::Coeffs(round_coeffs.clone());
		Ok(vec![round_coeffs])
	}

	fn fold(&mut self, challenge: F) -> Result<(), Error> {
		let RoundCoeffsOrEval::Coeffs(prime_coeffs) = &self.last_coeffs_or_eval else {
			return Err(Error::ExpectedExecute);
		};

		assert!(self.n_vars() > 0);

		let sum = prime_coeffs.evaluate(challenge);

		for multilinear in &mut self.multilinears {
			fold_highest_var_inplace(multilinear, challenge)?;
		}

		self.gruen34.fold(challenge)?;
		self.last_coeffs_or_eval = RoundCoeffsOrEval::Eval(sum);
		Ok(())
	}

	fn finish(self) -> Result<Vec<F>, Error> {
		if self.n_vars() > 0 {
			let error = match self.last_coeffs_or_eval {
				RoundCoeffsOrEval::Coeffs(_) => Error::ExpectedFold,
				RoundCoeffsOrEval::Eval(_) => Error::ExpectedExecute,
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

impl<F, P> MleCheckProver<F> for XSquaredYMinusXMlecheckProver<P>
where
	F: Field,
	P: PackedField<Scalar = F>,
{
	fn eval_point(&self) -> &[F] {
		&self.gruen34.eval_point()[..self.n_vars()]
	}
}

#[derive(Debug, Clone)]
enum RoundCoeffsOrEval<F: Field> {
	Coeffs(RoundCoeffs<F>),
	Eval(F),
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
			3, // degree 3 for x^2y-x
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
			multilinear_evals[0].square() * multilinear_evals[1] - multilinear_evals[0],
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
			4, // degree 4 for (x^2y-x)*eq
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
			(multilinear_evals[0].square() * multilinear_evals[1] - multilinear_evals[0])
				* eq_ind_eval,
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
	fn test_x2y_minus_x_mlecheck() {
		type F = OptimalB128;
		type P = OptimalPackedB128;

		let n_vars = 8;
		let mut rng = StdRng::seed_from_u64(0);

		// Generate two random multilinear polynomials
		let multilinear_a = random_field_buffer::<P>(&mut rng, n_vars);
		let multilinear_b = random_field_buffer::<P>(&mut rng, n_vars);

		// Compute product multilinear
		let composition = itertools::zip_eq(multilinear_a.as_ref(), multilinear_b.as_ref())
			.map(|(&l, &r)| l.square() * r - l)
			.collect_vec();
		let product_buffer = FieldBuffer::new(n_vars, composition).unwrap();

		let eval_point = random_scalars::<F>(&mut rng, n_vars);
		let eval_claim = evaluate(&product_buffer, &eval_point).unwrap();

		// Create the prover
		let mlecheck_prover = XSquaredYMinusXMlecheckProver::new(
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
