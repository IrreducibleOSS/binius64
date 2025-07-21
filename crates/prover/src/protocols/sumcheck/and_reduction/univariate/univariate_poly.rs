use binius_field::{
	AESTowerField8b, BinaryField128bPolyval, Field, arithmetic_traits::InvertOrZero,
};

use crate::protocols::sumcheck::and_reduction::univariate::{
	subfield_isomorphism::SubfieldIsomorphismLookup,
	univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_8b,
		lexicographic_lagrange_numerators_polyval,
	},
};
pub trait UnivariatePoly<FCoeffs: Field, FChallenge: Field> {
	fn iter_coeffs(&self) -> impl Iterator<Item = &FCoeffs>;

	fn evaluate_at_challenge(&self, challenge: FChallenge) -> FChallenge;

	fn evaluate_at_subfield_point(&self, challenge: FCoeffs) -> FCoeffs;

	fn degree_lt(&self) -> usize;
}

pub struct GenericPo2UnivariatePoly<'a, F: Field, FChallenge: Field> {
	univariate_lagrange_coeffs: Vec<F>,
	log_degree_lt: usize,
	lookup_table: &'a SubfieldIsomorphismLookup<FChallenge>,
}

impl<'a, F: Field, FChallenge: Field> GenericPo2UnivariatePoly<'a, F, FChallenge> {
	pub fn new(
		univariate_lagrange_coeffs: Vec<F>,
		iso_lookup: &'a SubfieldIsomorphismLookup<FChallenge>,
	) -> Self {
		let degree_lt = univariate_lagrange_coeffs.len();
		Self {
			univariate_lagrange_coeffs,
			log_degree_lt: degree_lt.trailing_zeros() as usize,
			lookup_table: iso_lookup,
		}
	}
}

impl UnivariatePoly<AESTowerField8b, BinaryField128bPolyval>
	for GenericPo2UnivariatePoly<'_, AESTowerField8b, BinaryField128bPolyval>
{
	fn iter_coeffs(&self) -> impl Iterator<Item = &AESTowerField8b> {
		self.univariate_lagrange_coeffs.iter()
	}

	fn evaluate_at_challenge(&self, challenge: BinaryField128bPolyval) -> BinaryField128bPolyval {
		let _span = tracing::debug_span!("evaluate_at_challenge").entered();

		let evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator =
			lexicographic_lagrange_numerators_polyval(
				self.degree_lt(),
				challenge,
				self.lookup_table,
			);

		(evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator
			.iter()
			.zip(self.iter_coeffs())
			.map(|(basis_vec_eval, coeff)| {
				*basis_vec_eval * self.lookup_table.lookup_8b_value(*coeff)
			})
			.sum::<BinaryField128bPolyval>())
			* self.lookup_table.lookup_8b_value(
				lexicographic_lagrange_denominator(self.log_degree_lt).invert_or_zero(),
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
		let _span = tracing::debug_span!("evaluate_at_challenge").entered();

		let evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator =
			lexicographic_lagrange_numerators_polyval(
				self.degree_lt(),
				challenge,
				self.lookup_table,
			);

		(evals_of_lagrange_basis_vectors_not_yet_divide_by_denominator
			.iter()
			.zip(self.iter_coeffs())
			.map(|(basis_vec_eval, coeff)| *basis_vec_eval * *coeff)
			.sum::<F>())
			* self.lookup_table.lookup_8b_value(
				lexicographic_lagrange_denominator(self.log_degree_lt).invert_or_zero(),
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
    use binius_field::{AESTowerField8b, BinaryField128bPolyval, PackedField, AESTowerField128b};
    use crate::protocols::sumcheck::and_reduction::univariate::subfield_isomorphism::SubfieldIsomorphismLookup;
    use super::GenericPo2UnivariatePoly;
    use crate::protocols::sumcheck::and_reduction::univariate::univariate_poly::UnivariatePoly;

    #[test]
    fn univariate_po2_sanity_check() {
        let iso_lookup: SubfieldIsomorphismLookup<BinaryField128bPolyval> = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

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
