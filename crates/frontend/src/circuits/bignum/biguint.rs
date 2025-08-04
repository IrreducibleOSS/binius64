use binius_core::word::Word;

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Represents an arbitrarily large unsigned integer using a vector of `Wire`s
///
/// - Each `Wire` holds a 64-bit unsigned integer value (a "limb")
/// - Limbs are stored in little-endian order (index 0 = least significant)
/// - The total bit width is always a multiple of 64 bits (number of limbs × 64)
#[derive(Clone)]
pub struct BigUint {
	pub limbs: Vec<Wire>,
}

impl BigUint {
	/// Creates a new BigUint with the given number of limbs as inout wires.
	pub fn new_inout(b: &CircuitBuilder, num_limbs: usize) -> Self {
		let limbs = (0..num_limbs).map(|_| b.add_inout()).collect();
		BigUint { limbs }
	}

	/// Creates a new Bignum with the given number of limbs as witness wires.
	pub fn new_witness(b: &CircuitBuilder, num_limbs: usize) -> Self {
		let limbs = (0..num_limbs).map(|_| b.add_witness()).collect();
		BigUint { limbs }
	}

	/// Populate the BigUint with the expected limb_values
	///
	/// Panics if limb_values.len() != self.limbs.len()
	pub fn populate_limbs(&self, w: &mut WitnessFiller, limb_values: &[u64]) {
		assert!(limb_values.len() == self.limbs.len());
		for (&wire, &v) in self.limbs.iter().zip(limb_values.iter()) {
			w[wire] = Word::from_u64(v);
		}
	}
}

/// Asserts that that two `BigUint`s are equal.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First operand `BigUint`
/// * `b` - Second operand `BigUint` (must have same number of limbs as `a`)
///
/// # Panics
/// Panics if `a` and `b` have different number of limbs.
pub fn assert_eq(builder: &CircuitBuilder, name: impl Into<String>, a: &BigUint, b: &BigUint) {
	assert_eq!(
		a.limbs.len(),
		b.limbs.len(),
		"biguint assert_eq: inputs must have the same number of limbs"
	);
	let base_name = name.into();
	for (i, (&a_l, &b_l)) in a.limbs.iter().zip(b.limbs.iter()).enumerate() {
		builder.assert_eq(format!("{base_name}[{i}]"), a_l, b_l);
	}
}
