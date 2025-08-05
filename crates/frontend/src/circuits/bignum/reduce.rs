use binius_core::word::Word;

use super::{
	addsub::{add, sub},
	biguint::{BigUint, assert_eq},
	mul::mul,
};
use crate::compiler::CircuitBuilder;

/// TODO: this should be moved from binius-verifier to binius-core
const WORD_SIZE_BITS: usize = 64;

/// Modular reduction verification for BigUint.
///
/// This circuit verifies that:
///
/// a = quotient * modulus + remainder
pub struct ModReduce {
	pub a: BigUint,
	pub modulus: BigUint,
	pub quotient: BigUint,
	pub remainder: BigUint,
}

impl ModReduce {
	/// Creates a new modular reduction verifier circuit.
	///
	/// # Arguments
	/// * `builder` - Circuit builder for constraint generation
	/// * `a` - The dividend
	/// * `modulus` - The divisor
	/// * `quotient` - The quotient
	/// * `remainder` - The remainder
	///
	/// # Constraints
	/// The circuit enforces that `a = quotient * modulus + remainder`
	pub fn new(
		builder: &CircuitBuilder,
		a: BigUint,
		modulus: BigUint,
		quotient: BigUint,
		remainder: BigUint,
	) -> Self {
		let zero = builder.add_constant(Word::ZERO);

		let product = mul(builder, &quotient, &modulus);

		let remainder_padded = remainder.pad_limbs_to(product.limbs.len(), zero);
		let reconstructed = add(builder, &product, &remainder_padded);

		let n_limbs = reconstructed.limbs.len().max(a.limbs.len());
		assert_eq(
			builder,
			"modreduce_a_eq_reconstructed",
			&reconstructed.pad_limbs_to(n_limbs, zero),
			&a.pad_limbs_to(n_limbs, zero),
		);

		ModReduce {
			a,
			modulus,
			quotient,
			remainder,
		}
	}
}

/// Modular reduction verification for BigUint for pseudo Mersenne moduli.
///
/// This circuit verifies that:
///
/// a = quotient * (2^modulus_po2 - modulus_subtrahend) + remainder
///
/// where modulus_po2 is additionally restricted to be a multiple of limb size to only
/// split BigUint at limb boundaries.
///
/// This algorithm is more efficient than `ModReduce` when `modulus_subtrahend` is a short
/// compared to `modulus_po2`. This is the case for many practically interesting prime field.
pub struct PseudoMersenneModReduce {
	pub a: BigUint,
	pub modulus_subtrahend: BigUint,
	pub quotient: BigUint,
	pub remainder: BigUint,
}

impl PseudoMersenneModReduce {
	/// Creates a new pseudo Mersenne modular reduction verifier circuit.
	///
	/// # Arguments
	/// * `builder` - Circuit builder for constraint generation
	/// * `a` - The dividend
	/// * `modulus_po2` - the power of two modulus minuend (has to be a multiple of
	///   `WORD_SIZE_BITS`)
	/// * `modulus_subtrahend` - the value subtracted form `2^modulus_po2` to obtain modulus
	/// * `quotient` - The quotient
	/// * `remainder` - The remainder
	///
	/// # Constraints
	/// The circuit enforces that `a = quotient * (2^modulus_po2 - modulus_subtrahend) + remainder`
	pub fn new(
		builder: &CircuitBuilder,
		a: BigUint,
		modulus_po2: usize,
		modulus_subtrahend: BigUint,
		quotient: BigUint,
		remainder: BigUint,
	) -> Self {
		// a = quotient * (2^modulus_po2 - modulus_subtrahend) + remainder
		// hi * 2^modulus_po2 + lo = quotient * (2^modulus_po2 - modulus_subtrahend) + remainder
		// lo + quotient * modulus_subtrahend = remainder + 2^modulus_po2 * (quotient - hi)
		// max(lo, remainder) < 2^modulus_po2
		// quotient < |a/(2^modulus_po2 - modulus_subtrahend)|
		// quotient >= hi
		assert!(modulus_po2.is_multiple_of(WORD_SIZE_BITS));
		assert!(modulus_subtrahend.limbs.len() * WORD_SIZE_BITS <= modulus_po2);
		assert!(remainder.limbs.len() * WORD_SIZE_BITS <= modulus_po2);

		let zero = builder.add_constant(Word::ZERO);

		let n_lo_limbs = modulus_po2 / WORD_SIZE_BITS;

		let (a_lo, a_hi) = a.pad_limbs_to(n_lo_limbs, zero).split_at_limbs(n_lo_limbs);

		let rhs_hi = sub(builder, &quotient, &a_hi.pad_limbs_to(quotient.limbs.len(), zero));
		let rhs = remainder
			.pad_limbs_to(n_lo_limbs, zero)
			.concat_limbs(&rhs_hi);

		let quotient_modulus_subtrahend = mul(builder, &quotient, &modulus_subtrahend);
		let lhs_rhs_len = [
			rhs.limbs.len(),
			quotient_modulus_subtrahend.limbs.len() + 1,
			a_lo.limbs.len() + 1,
		]
		.into_iter()
		.max()
		.expect("exactly 3 elements");

		let lhs = add(
			builder,
			&a_lo.pad_limbs_to(lhs_rhs_len, zero),
			&quotient_modulus_subtrahend.pad_limbs_to(lhs_rhs_len, zero),
		);

		assert_eq(builder, "modreduce_pseudo_mersenne", &lhs, &rhs.pad_limbs_to(lhs_rhs_len, zero));
		Self {
			a,
			modulus_subtrahend,
			quotient,
			remainder,
		}
	}
}
