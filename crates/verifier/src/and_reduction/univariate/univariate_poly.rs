use std::marker::PhantomData;

use binius_field::{
	Field,
};

use crate::and_reduction::{
	univariate::univariate_lagrange::{
		lexicographic_lagrange_denominator,
		lexicographic_lagrange_numerators_polyval,
	},
};

pub trait UnivariatePoly<FChallenge: Field> {
	fn evaluate_at_challenge(&self, challenge: FChallenge) -> FChallenge;
}

/// This is a univariate polynomial in lagrange basis with the evaluation points being field
/// elements in lexicographic order. The polynomial with coefficients in FChallenge isomorphic to
/// those of this polynomial can also be queried using methods on this struct
pub struct GenericPo2UnivariatePoly<F: Field + From<FNTTDomain>, FNTTDomain: Field> {
	univariate_lagrange_coeffs: Vec<F>,
	log_degree_lt: usize,
	_marker: PhantomData<FNTTDomain>
}

impl<F: Field + From<FNTTDomain>, FNTTDomain: Field> GenericPo2UnivariatePoly<F, FNTTDomain>
{
	pub fn new(
		univariate_lagrange_coeffs: Vec<F>,
	) -> Self {
		let degree_lt = univariate_lagrange_coeffs.len();
		Self {
			univariate_lagrange_coeffs,
			log_degree_lt: degree_lt.trailing_zeros() as usize,
    		_marker: PhantomData,
		}
	}

	fn degree_lt(&self) -> usize {
		1 << self.log_degree_lt
	}

	fn iter(&self) -> impl Iterator<Item = &F> {
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

impl<FNTTDomain, FCoeffs, FChallenge> UnivariatePoly<FChallenge>
	for GenericPo2UnivariatePoly<FCoeffs, FNTTDomain>
where FNTTDomain: Field+ From<u8>,
FCoeffs: Field + From<FNTTDomain>,
FChallenge: Field + From<FCoeffs> + From<FNTTDomain>
{
	fn evaluate_at_challenge(&self, challenge: FChallenge) -> FChallenge {
		let evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator =
			lexicographic_lagrange_numerators_polyval::<FNTTDomain,FChallenge>(
				self.degree_lt(),
				challenge,
			);

		let denominator_inv = FChallenge::from(
			lexicographic_lagrange_denominator::<FNTTDomain>(self.log_degree_lt).invert_or_zero(),
		);

		self.evaluate_lagrange_common(
			evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator.into_iter(),
			self.iter()
				.map(|coeff| FChallenge::from(*coeff)),
			denominator_inv,
		)
	}
}

#[cfg(test)]
mod test {
	use binius_field::{AESTowerField8b, BinaryField128bPolyval, PackedField};

	use super::GenericPo2UnivariatePoly;
	use crate::and_reduction::{
		univariate::univariate_poly::UnivariatePoly,
	};

	#[test]
	fn univariate_po2_sanity_check() {
		let v = (0..64)
			.map(AESTowerField8b::new)
			.map(|x| x.square())
			.collect();
		let poly = GenericPo2UnivariatePoly::<_,AESTowerField8b>::new(v);
		for i in 990..1000 {
			assert_eq!(
				poly.evaluate_at_challenge(BinaryField128bPolyval::from(i as u128)),
				BinaryField128bPolyval::from(i as u128).square()
			);
		}
	}
}
