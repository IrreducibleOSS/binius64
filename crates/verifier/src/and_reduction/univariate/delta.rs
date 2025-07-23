use binius_field::{Field, arithmetic_traits::InvertOrZero, AESTowerField8b};

use super::{
	univariate_lagrange::{
		lexicographic_lagrange_denominator, lexicographic_lagrange_numerators_polyval,
	},
	univariate_poly::GenericPo2UnivariatePoly,
};

pub fn delta_poly<FNTTDomain: Field + From<u8>, F: Field + From<FNTTDomain>>(
	zerocheck_challenge: F,
	log_degree_lt: usize,
) -> GenericPo2UnivariatePoly<F, FNTTDomain> {
	let mut univariate_lagrange_coeffs = lexicographic_lagrange_numerators_polyval::<FNTTDomain,F>(
		1 << log_degree_lt,
		zerocheck_challenge,
	);
	let lexicographic_lagrange_denominator_inv =
		lexicographic_lagrange_denominator::<FNTTDomain>(log_degree_lt).invert_or_zero();

	for coeff in &mut univariate_lagrange_coeffs {
		*coeff *= F::from(lexicographic_lagrange_denominator_inv);
	}

	GenericPo2UnivariatePoly::new(univariate_lagrange_coeffs)
}

#[cfg(test)]
mod tests {
	use binius_field::{AESTowerField8b, AESTowerField128b, BinaryField128bPolyval, Field};

	use crate::and_reduction::{
		univariate::{delta::delta_poly, univariate_poly::UnivariatePoly}, utils::constants::SKIPPED_VARS,
	};

	#[test]
	fn delta_satisfies_definition() {
		for i in 0..64 {
			let poly =
				delta_poly::<AESTowerField8b, BinaryField128bPolyval>(BinaryField128bPolyval::from(AESTowerField8b::new(i)), SKIPPED_VARS);
			for j in 0..64 {
				if i == j {
					assert_eq!(
						poly.evaluate_at_challenge(
							BinaryField128bPolyval::from(AESTowerField8b::new(j))
						),
						BinaryField128bPolyval::ONE
					);
				} else {
					assert_eq!(
						poly.evaluate_at_challenge(
							BinaryField128bPolyval::from(AESTowerField8b::new(j))
						),
						BinaryField128bPolyval::ZERO
					);
				}
			}
		}
	}
}
