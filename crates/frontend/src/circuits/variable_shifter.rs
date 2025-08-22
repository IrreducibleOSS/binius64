//! Variable right shift circuits using multiplexer-based selection.
//!
//! This module provides efficient circuit implementations for variable right shifts,
//! where both the value and shift amount are circuit wires (not compile-time constants).
//! The implementation uses a multiplexer approach that tests all possible shift values
//! and selects the correct result.

use super::multiplexer::single_wire_multiplex;
use crate::compiler::{CircuitBuilder, Wire};

/// Variable right shift for 64-bit values.
///
/// Performs a logical right shift of `x` by `shift` positions. This function handles
/// all valid shift amounts from 0 to 63. For shift amounts >= 64, returns 0.
///
/// # Implementation
///
/// Uses an optimal multiplexer tree to select from pre-computed shift results (0-63).
/// The multiplexer naturally wraps selectors using only the lower 6 bits, so an explicit
/// check for shift >= 64 ensures correct semantics (returning 0 instead of wrapping).
pub fn shr_var(builder: &mut CircuitBuilder, x: Wire, shift: Wire) -> Wire {
	// Create all possible shifted results (0-63)
	let shifted_results: Vec<Wire> = (0..64)
		.map(|shift_val| builder.shr(x, shift_val as u32))
		.collect();

	// Use multiplexer to select based on shift value
	let result = single_wire_multiplex(builder, &shifted_results, shift);

	// Handle shift >= 64: if shift >= 64, return 0
	let shift_ge_64 = builder.bnot(builder.icmp_ult(shift, builder.add_constant_64(64)));
	builder.select(result, builder.add_constant_64(0), shift_ge_64)
}

/// Variable right shift with sticky bit computation.
///
/// Performs a logical right shift of `x` by `shift` positions and computes a "sticky bit"
/// that indicates whether any 1-bits were shifted out (lost). This is essential for
/// floating-point rounding and precision tracking.
///
/// # Sticky bit semantics
///
/// The sticky bit is 1 if any bits would be lost during the shift:
/// - For shift == 0: sticky = 0 (no bits lost)
/// - For 1 <= shift <= 63: sticky = 1 if any of the low `shift` bits of `x` are 1
/// - For shift >= 64: sticky = 1 if `x != 0` (all bits would be lost)
///
/// # Implementation
///
/// Uses efficient multiplexer trees to select from pre-computed shift results and
/// sticky bit values, avoiding sequential comparisons for optimal circuit depth.
/// Like `shr_var`, requires explicit shift >= 64 handling since multiplexers wrap
/// selectors using only the lower 6 bits (would return x >> (shift & 63) instead of 0).
///
/// # Arguments
///
/// * `builder` - Circuit builder for creating wires and constraints
/// * `x` - The 64-bit value to shift (as a circuit wire)
/// * `shift` - The shift amount (as a circuit wire)
///
/// # Returns
///
/// A tuple `(shifted_value, sticky_bit)` where:
/// - `shifted_value` is the same as `shr_var(builder, x, shift)`
/// - `sticky_bit` is 1 if any bits were lost, 0 otherwise
pub fn shr_var_with_sticky(builder: &mut CircuitBuilder, x: Wire, shift: Wire) -> (Wire, Wire) {
	let zero = builder.add_constant_64(0);
	let one = builder.add_constant_64(1);

	// Create all possible shifted results (0-63) and sticky bits
	let shifted_results: Vec<Wire> = (0..64)
		.map(|shift_val| builder.shr(x, shift_val as u32))
		.collect();

	let sticky_results: Vec<Wire> = (0..64)
		.map(|shift_val| {
			if shift_val == 0 {
				zero
			} else {
				let mask = builder.add_constant_64((1u64 << shift_val) - 1);
				let lost_bits = builder.band(x, mask);
				let bits_are_zero = builder.icmp_eq(lost_bits, zero);
				builder.select(one, zero, bits_are_zero)
			}
		})
		.collect();

	// Use multiplexers to select based on shift value
	let result = single_wire_multiplex(builder, &shifted_results, shift);
	let sticky = single_wire_multiplex(builder, &sticky_results, shift);

	// Handle shift >= 64: result=0, sticky=1 if x!=0
	let shift_ge_64 = builder.bnot(builder.icmp_ult(shift, builder.add_constant_64(64)));
	let large_shift_sticky = builder.select(one, zero, builder.icmp_eq(x, zero));
	let final_result = builder.select(result, zero, shift_ge_64);
	let final_sticky = builder.select(sticky, large_shift_sticky, shift_ge_64);

	(final_result, final_sticky)
}

#[cfg(test)]
mod tests {
	use binius_core::Word;
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	/// Test harness for shr_var function
	fn test_shr_var(x_val: u64, shift_val: u64) {
		let expected_result = if shift_val >= 64 {
			0
		} else {
			x_val >> shift_val
		};

		let mut builder = CircuitBuilder::new();
		let x_wire = builder.add_inout();
		let shift_wire = builder.add_inout();
		let result_wire = shr_var(&mut builder, x_wire, shift_wire);

		builder.assert_eq(
			"shr_var result matches expected x={x_val} shift={shift_val}",
			result_wire,
			builder.add_constant_64(expected_result),
		);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();
		filler[x_wire] = Word(x_val);
		filler[shift_wire] = Word(shift_val);
		circuit.populate_wire_witness(&mut filler).unwrap();

		let constraint_system = circuit.constraint_system();
		verify_constraints(constraint_system, &filler.into_value_vec()).unwrap();
	}

	/// Test harness for shr_var_with_sticky function
	fn test_shr_var_with_sticky(x_val: u64, shift_val: u64) {
		let expected_result = if shift_val >= 64 {
			0
		} else {
			x_val >> shift_val
		};
		let expected_sticky = if shift_val == 0 {
			0
		} else if shift_val >= 64 {
			if x_val == 0 { 0 } else { 1 }
		} else {
			let mask = (1u64 << shift_val) - 1;
			if (x_val & mask) != 0 { 1 } else { 0 }
		};

		let mut builder = CircuitBuilder::new();
		let x_wire = builder.add_inout();
		let shift_wire = builder.add_inout();
		let (result_wire, sticky_wire) = shr_var_with_sticky(&mut builder, x_wire, shift_wire);

		builder.assert_eq(
			"sticky shifter result matches expected x={x_val} shift={shift_val}",
			result_wire,
			builder.add_constant_64(expected_result),
		);
		builder.assert_eq(
			"sticky shifter sticky matches expected x={x_val} shift={shift_val}",
			sticky_wire,
			builder.add_constant_64(expected_sticky),
		);

		let circuit = builder.build();
		let mut filler = circuit.new_witness_filler();
		filler[x_wire] = Word(x_val);
		filler[shift_wire] = Word(shift_val);
		circuit.populate_wire_witness(&mut filler).unwrap();

		let constraint_system = circuit.constraint_system();
		verify_constraints(constraint_system, &filler.into_value_vec()).unwrap();
	}

	#[test]
	fn test_shifters_comprehensive() {
		let mut rng = StdRng::seed_from_u64(0);

		// Edge case values that are likely to reveal bugs
		let edge_values = [0, 1, u64::MAX, 0x8000000000000000];

		// Test shr_var with edge cases and all shift values
		for &x_val in &edge_values {
			for shift_val in [0, 1, 2, 31, 32, 63, 64, 65, 100] {
				test_shr_var(x_val, shift_val);
			}
		}

		// Test shr_var with random values and shifts
		for _ in 0..30 {
			let x_val: u64 = rng.random();
			let shift_val = rng.random_range(0..=80);
			test_shr_var(x_val, shift_val);
		}

		// Test shr_var_with_sticky with edge cases
		for &x_val in &edge_values {
			for shift_val in [0, 1, 2, 31, 32, 63, 64, 65, 100] {
				test_shr_var_with_sticky(x_val, shift_val);
			}
		}

		// Additional testing for sticky shifter with special bit patterns
		let bit_patterns = [
			0x5555555555555555, // Alternating 01 pattern
			0xAAAAAAAAAAAAAAAA, // Alternating 10 pattern
			0x00000000FFFFFFFF, // Low 32 bits set
			0xFFFFFFFF00000000, // High 32 bits set
		];

		for &pattern in &bit_patterns {
			for shift_val in [0, 1, 2, 16, 32, 48, 63, 64, 80] {
				test_shr_var_with_sticky(pattern, shift_val);
			}
		}

		// Random testing for sticky shifter
		for _ in 0..30 {
			let x_val: u64 = rng.random();
			let shift_val = rng.random_range(0..=80);
			test_shr_var_with_sticky(x_val, shift_val);
		}
	}
}
