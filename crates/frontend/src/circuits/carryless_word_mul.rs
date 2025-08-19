//! Carryless multiplication circuit implementation.
//!
//! This module provides carryless multiplication for 64-bit words, for now intended
//! to simulate GHASH multiplication operations. Eventually, we plan to add a native
//! GHASH multiplication circuit that will be more efficient.

use binius_core::word::Word;

use crate::{
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::bool_to_mask,
};

/// Creates a carryless multiplication circuit.
///
/// Performs polynomial multiplication in GF(2): a ⊗ b = hi || lo where ⊗ is carryless
/// multiplication.
///
/// # Parameters
/// * `builder` - Circuit builder for creating constraints
/// * `a` - First 64-bit operand wire
/// * `b` - Second 64-bit operand wire
///
/// # Returns
/// `(lo, hi)` - 128-bit result as (low 64 bits, high 64 bits)
pub fn carryless_mul(builder: &CircuitBuilder, a: Wire, b: Wire) -> (Wire, Wire) {
	// Carryless multiplication: for each bit i set in b, XOR (a << i) into result
	// Equivalent to polynomial multiplication in GF(2) where addition is XOR

	let zero = builder.add_constant(Word::ZERO);

	// 128-bit result accumulator split into low and high 64-bit words
	let mut acc_lo = zero;
	let mut acc_hi = zero;

	// For each bit position i in operand b (from LSB to MSB)
	for i in 0..64 {
		// Extract bit i of b: shift bit i to MSB position, then create mask
		// If bit i is 1, mask is all 1s; if bit i is 0, mask is all 0s
		let bit_is_one_mask = bool_to_mask(builder, builder.shl(b, (63 - i) as u32));

		// Compute (a << i) split into 64-bit low and high parts
		let a_shifted_lo = builder.shl(a, i as u32);
		let a_shifted_hi = if i == 0 {
			zero // No overflow when i=0
		} else {
			builder.shr(a, (64 - i) as u32) // Bits that overflow from low word
		};

		// Apply mask: include shifted_a only if bit i of b is set
		let masked_lo = builder.band(a_shifted_lo, bit_is_one_mask);
		let masked_hi = builder.band(a_shifted_hi, bit_is_one_mask);

		// XOR into accumulator (carryless addition)
		acc_lo = builder.bxor(acc_lo, masked_lo);
		acc_hi = builder.bxor(acc_hi, masked_hi);
	}

	(acc_lo, acc_hi)
}

/// Populates witness values for carryless multiplication output wires.
///
/// # Parameters
/// * `w` - Witness filler to populate
/// * `lo` - Low 64-bit output wire (from `carryless_mul`)
/// * `hi` - High 64-bit output wire (from `carryless_mul`)
/// * `a_val` - Value for first operand
/// * `b_val` - Value for second operand
pub fn populate_carryless_mul_outputs(
	w: &mut WitnessFiller,
	lo: Wire,
	hi: Wire,
	a_val: u64,
	b_val: u64,
) {
	let (lo_val, hi_val) = carryless_mul_u64(a_val, b_val);

	w[lo] = Word(lo_val);
	w[hi] = Word(hi_val);
}

/// Software implementation of 64x64 carryless multiplication returning 128-bit result as (lo, hi)
pub fn carryless_mul_u64(a: u64, b: u64) -> (u64, u64) {
	let mut lo = 0u64;
	let mut hi = 0u64;

	// For each bit position in b
	for i in 0..64 {
		if (b >> i) & 1 == 1 {
			// Add a << i to the result (carryless)
			// Low part: just shift left, overflow is handled naturally by u64
			lo ^= a << i;

			// High part: bits that shifted out of the low 64 bits
			if i > 0 {
				hi ^= a >> (64 - i);
			}
		}
	}

	(lo, hi)
}

#[cfg(test)]
mod tests {
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	#[test]
	fn test_carryless_mul_software() {
		let mut rng = StdRng::seed_from_u64(0);
		let a = rng.random::<u64>();
		let b = rng.random::<u64>();
		let (lo, hi) = carryless_mul_u64(a, b);

		let mut expected_result = 0u128;
		for i in 0..64 {
			if (b >> i) & 1 == 1 {
				expected_result ^= (a as u128) << i;
			}
		}
		let expected_hi = (expected_result >> 64) as u64;
		let expected_lo = expected_result as u64;

		assert_eq!((lo, hi), (expected_lo, expected_hi));

		// Test edge cases
		assert_eq!(carryless_mul_u64(0, rng.random::<u64>()), (0, 0));
		assert_eq!(carryless_mul_u64(rng.random::<u64>(), 0), (0, 0));
	}

	#[test]
	fn test_carryless_mul_circuit() {
		let mut rng = StdRng::seed_from_u64(0);
		let builder = CircuitBuilder::new();

		let a = builder.add_witness();
		let b = builder.add_witness();

		let (lo, hi) = carryless_mul(&builder, a, b);
		let circuit = builder.build();

		let a_val = rng.random::<u64>();
		let b_val = rng.random::<u64>();

		let mut witness = circuit.new_witness_filler();
		witness[a] = Word(a_val);
		witness[b] = Word(b_val);

		populate_carryless_mul_outputs(&mut witness, lo, hi, a_val, b_val);

		circuit.populate_wire_witness(&mut witness).unwrap();
		let constraints = circuit.constraint_system();
		verify_constraints(constraints, &witness.into_value_vec()).unwrap();
	}
}
