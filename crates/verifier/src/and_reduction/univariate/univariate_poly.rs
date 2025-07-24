use std::marker::PhantomData;

use binius_field::Field;

use crate::and_reduction::univariate::univariate_lagrange::{
	lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_polyval,
};

pub trait UnivariatePoly<FChallenge: Field> {
	fn evaluate_at_challenge(&self, challenge: FChallenge) -> FChallenge;
}

/// This is a univariate polynomial in lagrange basis with the evaluation points being field
/// elements in lexicographic order forming an F2-subspace of FDomain.
/// The polynomial with lagrange coefficients in FChallenge isomorphic to
/// those of this polynomial can also be queried using methods on this struct
pub struct GenericPo2UnivariatePoly<F: Field + From<FDomain>, FDomain: Field> {
	univariate_lagrange_coeffs: Vec<F>,
	log_degree_lt: usize,
	_marker: PhantomData<FDomain>,
}

impl<FCoeffs: Field + From<FDomain>, FDomain: Field> GenericPo2UnivariatePoly<FCoeffs, FDomain> {
	pub fn new(univariate_lagrange_coeffs: Vec<FCoeffs>) -> Self {
		let degree_lt = univariate_lagrange_coeffs.len();
		Self {
			univariate_lagrange_coeffs,
			log_degree_lt: degree_lt.trailing_zeros() as usize,
			_marker: PhantomData,
		}
	}

	pub fn degree_lt(&self) -> usize {
		1 << self.log_degree_lt
	}

	pub fn iter(&self) -> impl Iterator<Item = &FCoeffs> {
		self.univariate_lagrange_coeffs.iter()
	}

	fn evaluate_lagrange_common<FEval: Field>(
		&self,
		numerators: impl Iterator<Item = FEval>,
		coeffs_in_eval_field: impl Iterator<Item = FEval>,
		denominator_inv_in_eval_field: FEval,
	) -> FEval {
		numerators
			.zip(coeffs_in_eval_field)
			.map(|(basis_vec_eval, coeff)| basis_vec_eval * coeff)
			.sum::<FEval>()
			* denominator_inv_in_eval_field
	}
}

impl<FDomain, FCoeffs, FChallenge> UnivariatePoly<FChallenge>
	for GenericPo2UnivariatePoly<FCoeffs, FDomain>
where
	FDomain: Field + From<u8>,
	FCoeffs: Field + From<FDomain>,
	FChallenge: Field + From<FCoeffs> + From<FDomain>,
{
	fn evaluate_at_challenge(&self, challenge: FChallenge) -> FChallenge {
		let evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator =
			lexicographic_lagrange_numerators_polyval::<FDomain, FChallenge>(
				self.degree_lt(),
				challenge,
			);

		let denominator_inv = FChallenge::from(
			lexicographic_lagrange_denominator::<FDomain>(self.log_degree_lt).invert_or_zero(),
		);

		self.evaluate_lagrange_common(
			evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator.into_iter(),
			self.iter().map(|coeff| FChallenge::from(*coeff)),
			denominator_inv,
		)
	}
}

#[cfg(test)]
mod test {
	use binius_field::{AESTowerField8b, Random};
	use itertools::Itertools;
	use rand::{SeedableRng, rngs::StdRng};

	use super::GenericPo2UnivariatePoly;
	use crate::{
		and_reduction::univariate::univariate_poly::UnivariatePoly, fields::B128,
		protocols::sumcheck::RoundCoeffs,
	};

	#[test]
	fn univariate_po2_sanity_check() {
		let mut rng = StdRng::from_seed([0; 32]);

		let monomial_basis_coeffs = (0..64)
			.map(|_| AESTowerField8b::random(&mut rng))
			.collect_vec();
		let monomial_basis_poly = RoundCoeffs(monomial_basis_coeffs.clone());

		let monomial_basis_coeffs_isomorphic = monomial_basis_coeffs
			.into_iter()
			.map(|monomial_basis_coeff| B128::from(monomial_basis_coeff))
			.collect_vec();

		let monomial_basis_isomorphic = RoundCoeffs(monomial_basis_coeffs_isomorphic);

		let v = (0..64)
			.map(AESTowerField8b::new)
			.map(|x| monomial_basis_poly.evaluate(x))
			.collect();

		let poly = GenericPo2UnivariatePoly::<_, AESTowerField8b>::new(v);

		let random_point = B128::random(&mut rng);

		assert_eq!(
			poly.evaluate_at_challenge(random_point),
			monomial_basis_isomorphic.evaluate(random_point)
		);
	}
}
