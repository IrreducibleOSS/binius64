use binius_core::word::Word;

use super::{
	add::add,
	biguint::{BigUint, assert_eq},
	mul::mul,
};
use crate::compiler::CircuitBuilder;

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

		let mut remainder_padded = remainder.limbs.clone();
		remainder_padded.resize(product.limbs.len(), zero);
		let remainder_padded = BigUint {
			limbs: remainder_padded,
		};

		let reconstructed = add(builder, &product, &remainder_padded);

		let mut a_padded = a.limbs.clone();
		a_padded.resize(reconstructed.limbs.len(), zero);
		let a_padded = BigUint { limbs: a_padded };

		assert_eq(builder, "modreduce_a_eq_reconstructed", &reconstructed, &a_padded);

		ModReduce {
			a,
			modulus,
			quotient,
			remainder,
		}
	}
}
