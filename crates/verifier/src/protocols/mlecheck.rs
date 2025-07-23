use binius_field::Field;

use crate::protocols::sumcheck::RoundCoeffs;

/// An MLE-check round proof is a univariate polynomial in monomial basis with the coefficient of
/// the lowest-degree term truncated off.
///
/// Since the verifier knows the claimed linear extrapolation of the polynomial values at the
/// points 0 and 1, the low-degree term coefficient can be easily recovered. Truncating the
/// coefficient off saves a small amount of proof data.
///
/// This is an analogous struct to [`crate::protocols::sumcheck::RoundProof`], except that we
/// truncate the low-degree coefficient instead of the high-degree coefficient.
///
/// In a sumcheck protocol, the verifier has a claimed sum $s$ and the round polynomial $R(X)$ must
/// satisfy $R(0) + R(1) = s$. In an MLE-check protocol, the verifier has a claimed coordinate
/// $\alpha$ and extrapolated value $s$ and the round polynomial must satisfy
/// $(1 - \alpha) R(0) + \alpha R(1) = s$. This difference changes the recovery procedure and which
/// polynomial coefficient is most convenient to truncate.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RoundProof<F: Field>(pub RoundCoeffs<F>);

impl<F: Field> RoundProof<F> {
	/// Truncates the polynomial coefficients to a round proof.
	///
	/// Removes the first coefficient. See the struct documentation for more info.
	///
	/// ## Pre-conditions
	///
	/// * `coeffs` must not be empty
	pub fn truncate(mut coeffs: RoundCoeffs<F>) -> Self {
		coeffs.0.remove(0);
		Self(coeffs)
	}

	/// Recovers all univariate polynomial coefficients from the compressed round proof.
	///
	/// The prover has sent coefficients for the purported $i$'th round polynomial
	/// $R(X) = \sum_{j=0}^d a_j * X^j$.
	///
	/// However, the prover has not sent the lowest degree coefficient $a_0$. The verifier will
	/// need to recover this missing coefficient.
	///
	/// Let $s$ denote the current round's claimed sum and $\alpha_i$ be the $i$'th coordinate of
	/// the evaluation point.
	///
	/// The verifier expects the round polynomial $R_i$ to satisfy the identity
	/// $s = (1 - \alpha) R(0) + \alpha R(1)$, or equivalently, $s = R(0) + (R(1) - R(0)) \alpha$.
	///
	/// Using
	///     $R(0) = a_0$
	///     $R(1) = \sum_{j=0}^d a_j$
	/// There is a unique $a_0$ that allows $R$ to satisfy the above identity. Specifically,
	/// $a_0 = s - \alpha \sum_{j=1}^d a_j$.
	pub fn recover(self, eval: F, alpha: F) -> RoundCoeffs<F> {
		let Self(RoundCoeffs(mut coeffs)) = self;
		let first_coeff = eval - alpha * coeffs.iter().sum::<F>();
		coeffs.insert(0, first_coeff);
		RoundCoeffs(coeffs)
	}

	/// The truncated polynomial coefficients.
	pub fn coeffs(&self) -> &[F] {
		&self.0.0
	}
}

#[cfg(test)]
mod tests {
	use binius_field::Random;
	use binius_math::{line::extrapolate_line_packed, test_utils::random_scalars};
	use rand::prelude::*;

	use super::*;
	use crate::fields::B128;

	fn test_recover_with_degree<F: Field>(mut rng: impl Rng, alpha: F, degree: usize) {
		let coeffs = RoundCoeffs(random_scalars(&mut rng, degree + 1));

		let v0 = coeffs.evaluate(F::ZERO);
		let v1 = coeffs.evaluate(F::ONE);
		let eval = extrapolate_line_packed(v0, v1, alpha);

		let proof = RoundProof::truncate(coeffs.clone());
		assert_eq!(proof.recover(eval, alpha), coeffs);
	}

	#[test]
	fn test_recover() {
		let mut rng = StdRng::seed_from_u64(0);
		let alpha = B128::random(&mut rng);

		for degree in 0..4 {
			// Test with random coordinate
			test_recover_with_degree(&mut rng, alpha, degree);

			// Test edge case coordinate values
			test_recover_with_degree(&mut rng, B128::ZERO, degree);
			test_recover_with_degree(&mut rng, B128::ONE, degree);
		}
	}
}
