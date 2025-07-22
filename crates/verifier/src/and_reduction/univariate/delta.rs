use binius_field::{Field, arithmetic_traits::InvertOrZero};

use super::{
	univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_polyval,
	},
	univariate_poly::GenericPo2UnivariatePoly,
};
use crate::and_reduction::utils::subfield_isomorphism::SubfieldIsomorphismLookup;

pub fn delta_poly<'a, F: Field>(
	zerocheck_challenge: F,
	log_degree_lt: usize,
	iso_lookup: &'a SubfieldIsomorphismLookup<F>,
) -> GenericPo2UnivariatePoly<'a, F, F> {
	let mut univariate_lagrange_coeffs = lexicographic_lagrange_numerators_polyval(
		1 << log_degree_lt,
		zerocheck_challenge,
		iso_lookup,
	);
	let lexicographic_lagrange_denominator_inv =
		lexicographic_lagrange_denominator(log_degree_lt).invert_or_zero();

	for coeff in &mut univariate_lagrange_coeffs {
		*coeff *= iso_lookup.lookup_8b_value(lexicographic_lagrange_denominator_inv);
	}

	GenericPo2UnivariatePoly::new(univariate_lagrange_coeffs, iso_lookup)
}

#[cfg(test)]
mod tests {
	use binius_field::{AESTowerField8b, AESTowerField128b, BinaryField128bPolyval, Field};

	use crate::and_reduction::{univariate::{
		delta::delta_poly,
		univariate_poly::UnivariatePoly,
	}, utils::subfield_isomorphism::SubfieldIsomorphismLookup};

	#[test]
	fn delta_satisfies_definition() {
		let iso_lookup =
			SubfieldIsomorphismLookup::<BinaryField128bPolyval>::new::<AESTowerField128b>();
		for i in 0..64 {
			let poly =
				delta_poly(iso_lookup.lookup_8b_value(AESTowerField8b::new(i)), 6, &iso_lookup);
			for j in 0..64 {
				if i == j {
					assert_eq!(
						poly.evaluate_at_challenge(
							iso_lookup.lookup_8b_value(AESTowerField8b::new(j))
						),
						BinaryField128bPolyval::ONE
					);
				} else {
					assert_eq!(
						poly.evaluate_at_challenge(
							iso_lookup.lookup_8b_value(AESTowerField8b::new(j))
						),
						BinaryField128bPolyval::ZERO
					);
				}
			}
		}
	}
}
