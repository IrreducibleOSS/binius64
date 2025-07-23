use binius_field::{
	AESTowerField8b, BinaryField128bPolyval, Field, arithmetic_traits::InvertOrZero,
};

use crate::and_reduction::{
	univariate::univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_8b,
		lexicographic_lagrange_numerators_polyval,
	},
	utils::subfield_isomorphism::SubfieldIsomorphismLookup,
};

pub trait UnivariatePoly<FCoeffs: Field, FChallenge: Field> {
	fn iter_coeffs(&self) -> impl Iterator<Item = &FCoeffs>;

	fn evaluate_at_challenge(&self, challenge: FChallenge) -> FChallenge;

	fn evaluate_at_subfield_point(&self, challenge: FCoeffs) -> FCoeffs;

	fn degree_lt(&self) -> usize;
}

/// This is a univariate polynomial in lagrange basis with the evaluation points being field
/// elements in lexicographic order. The polynomial with coefficients in FChallenge isomorphic to
/// those of this polynomial can also be queried using methods on this struct
pub struct GenericPo2UnivariatePoly<F: Field> {
	univariate_lagrange_coeffs: Vec<F>,
	log_degree_lt: usize,
}

impl<'a, F: Field> GenericPo2UnivariatePoly<F>
{
	pub fn new(
		univariate_lagrange_coeffs: Vec<F>,
	) -> Self {
		let degree_lt = univariate_lagrange_coeffs.len();
		Self {
			univariate_lagrange_coeffs,
			log_degree_lt: degree_lt.trailing_zeros() as usize,
		}
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

impl UnivariatePoly<AESTowerField8b, BinaryField128bPolyval>
	for GenericPo2UnivariatePoly<AESTowerField8b>
{
	fn iter_coeffs(&self) -> impl Iterator<Item = &AESTowerField8b> {
		self.univariate_lagrange_coeffs.iter()
	}

	fn evaluate_at_challenge(&self, challenge: BinaryField128bPolyval) -> BinaryField128bPolyval {
		let evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator =
			lexicographic_lagrange_numerators_polyval(
				self.degree_lt(),
				challenge,
			);

		let denominator_inv = self.lookup_table.lookup_8b_value(
			lexicographic_lagrange_denominator(self.log_degree_lt).invert_or_zero(),
		);

		self.evaluate_lagrange_common(
			evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator.into_iter(),
			self.iter_coeffs()
				.map(|coeff| self.lookup_table.lookup_8b_value(*coeff)),
			denominator_inv,
		)
	}

	fn evaluate_at_subfield_point(&self, challenge: AESTowerField8b) -> AESTowerField8b {
		let evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator =
			lexicographic_lagrange_numerators_8b(self.degree_lt(), challenge);

		(evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator
			.iter()
			.zip(self.iter_coeffs())
			.map(|(basis_vec_eval, coeff)| *coeff * *basis_vec_eval)
			.sum::<AESTowerField8b>())
			* (lexicographic_lagrange_denominator(self.log_degree_lt).invert_or_zero())
	}

	fn degree_lt(&self) -> usize {
		1 << self.log_degree_lt
	}
}

impl<F: Field> UnivariatePoly<F, F> for GenericPo2UnivariatePoly<'_, F, F> {
	fn iter_coeffs(&self) -> impl Iterator<Item = &F> {
		self.univariate_lagrange_coeffs.iter()
	}

	fn evaluate_at_challenge(&self, challenge: F) -> F {
		let evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator =
			lexicographic_lagrange_numerators_polyval(
				self.degree_lt(),
				challenge,
				self.lookup_table,
			);

		let denominator_inv = self.lookup_table.lookup_8b_value(
			lexicographic_lagrange_denominator(self.log_degree_lt).invert_or_zero(),
		);

		self.evaluate_lagrange_common(
			evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator.into_iter(),
			self.iter_coeffs().cloned(),
			denominator_inv,
		)
	}

	fn evaluate_at_subfield_point(&self, challenge: F) -> F {
		self.evaluate_at_challenge(challenge)
	}

	fn degree_lt(&self) -> usize {
		1 << self.log_degree_lt
	}
}

#[cfg(test)]
mod test {
	use binius_field::{AESTowerField8b, AESTowerField128b, BinaryField128bPolyval, PackedField};

	use super::GenericPo2UnivariatePoly;
	use crate::and_reduction::{
		univariate::univariate_poly::UnivariatePoly,
		utils::subfield_isomorphism::SubfieldIsomorphismLookup,
	};

	#[test]
	fn univariate_po2_sanity_check() {
		let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

		let v = (0..64)
			.map(AESTowerField8b::new)
			.map(|x| x.square())
			.collect();
		let poly = GenericPo2UnivariatePoly::new(v, &iso_lookup);
		for i in 990..1000 {
			assert_eq!(
				poly.evaluate_at_challenge(BinaryField128bPolyval::from(i as u128)),
				BinaryField128bPolyval::from(i as u128).square()
			);
		}
	}
}
