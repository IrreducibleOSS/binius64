//! Byte manipulation circuits for Binius64.
//!
//! This module provides utility functions for byte-level operations on 64-bit words,
//! including byte swapping (endianness conversion).

use crate::compiler::{CircuitBuilder, Wire};

/// Reverses the byte order of a 64-bit word.
///
/// This function swaps the bytes of the input word, converting between
/// little-endian and big-endian representations. It implements the same
/// operation as the Rust standard library's `u64::swap_bytes()`.
///
/// # Algorithm
///
/// The implementation uses the Hacker's Delight bit manipulation algorithm,
/// performing byte swapping through three passes of masking and swapping at
/// increasing granularities:
///
/// 1. **Pass 1**: Swap adjacent bytes (8-bit units)
///    - Mask: `0x00FF00FF00FF00FF`
///    - Operation: `((x & mask) << 8) | ((x >> 8) & mask)`
///
/// 2. **Pass 2**: Swap adjacent 16-bit units (words)
///    - Mask: `0x0000FFFF0000FFFF`
///    - Operation: `((x & mask) << 16) | ((x >> 16) & mask)`
///
/// 3. **Pass 3**: Swap 32-bit halves
///    - No mask needed
///    - Operation: `(x << 32) | (x >> 32)`
///
/// This approach efficiently reverses byte order using only shifts, masks, and XOR
/// operations, avoiding the need for byte extraction.
///
/// # Arguments
/// * `builder` - The circuit builder to add constraints to
/// * `input` - Wire containing the 64-bit value to swap bytes of
///
/// # Returns
/// * Wire containing the byte-swapped result
///
/// # Cost Analysis
/// * 6 shift operations (3 left shifts, 3 right shifts)
/// * 4 bitwise AND operations (masking)
/// * 3 bitwise XOR operations (combining)
///
/// All shifts are free in Binius64 when part of constraints, making this
/// approach very efficient.
///
/// # Example
///
/// ```rust,ignore
/// use binius_core::word::Word;
/// use binius_frontend::circuits::bytes::swap_bytes;
/// use binius_frontend::compiler::CircuitBuilder;
///
/// // Build circuit
/// let mut builder = CircuitBuilder::new();
/// let input = builder.add_witness();
/// let output = builder.add_witness();
/// let swapped = swap_bytes(&builder, input);
/// builder.assert_eq("swap_bytes_result", swapped, output);
/// let circuit = builder.build();
///
/// // Fill witness
/// let mut w = circuit.new_witness_filler();
/// w[input] = Word(0x0123456789ABCDEF);
/// w[output] = Word(0xEFCDAB8967452301);  // Bytes reversed
///
/// // Verify
/// circuit.populate_wire_witness(&mut w).unwrap();
/// ```
///
/// # Reference
/// Based on the byte swapping algorithm from "Hacker's Delight" by Henry S. Warren Jr.
pub fn swap_bytes(builder: &CircuitBuilder, input: Wire) -> Wire {
	// Create constant masks for each pass
	let mask_00ff = builder.add_constant_64(0x00FF00FF00FF00FF);
	let mask_0000ffff = builder.add_constant_64(0x0000FFFF0000FFFF);

	// Pass 1: Swap adjacent bytes
	// x = ((x & 0x00FF00FF00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF00FF00FF)
	let masked_input_bytes = builder.band(input, mask_00ff);
	let shl_8 = builder.shl(masked_input_bytes, 8);
	let shr_8 = builder.shr(input, 8);
	let masked_shr_8 = builder.band(shr_8, mask_00ff);
	let step1 = builder.bxor(shl_8, masked_shr_8);

	// Pass 2: Swap adjacent 16-bit units
	// x = ((x & 0x0000FFFF0000FFFF) << 16) | ((x >> 16) & 0x0000FFFF0000FFFF)
	let masked_step1_words = builder.band(step1, mask_0000ffff);
	let shl_16 = builder.shl(masked_step1_words, 16);
	let shr_16 = builder.shr(step1, 16);
	let masked_shr_16 = builder.band(shr_16, mask_0000ffff);
	let step2 = builder.bxor(shl_16, masked_shr_16);

	// Pass 3: Swap 32-bit halves
	// x = (x << 32) | (x >> 32)
	// No masking needed since we're swapping the entire halves
	let shl_32 = builder.shl(step2, 32);
	let shr_32 = builder.shr(step2, 32);
	builder.bxor(shl_32, shr_32)
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;
	use proptest::prelude::*;

	use super::*;
	use crate::constraint_verifier::verify_constraints;

	/// Helper function to test swap_bytes circuit with given input and expected output
	fn test_swap_bytes_helper(input_val: u64, expected: u64) {
		let builder = CircuitBuilder::new();
		let input = builder.add_witness();
		let output = builder.add_witness();
		let swapped = swap_bytes(&builder, input);
		builder.assert_eq("swap_bytes_result", swapped, output);
		let circuit = builder.build();

		let mut w = circuit.new_witness_filler();
		w[input] = Word(input_val);
		w[output] = Word(expected);

		circuit.populate_wire_witness(&mut w).unwrap();
		verify_constraints(circuit.constraint_system(), &w.value_vec).unwrap();
	}

	proptest! {
		#[test]
		fn test_swap_bytes_random(input_val: u64) {
			let expected = input_val.swap_bytes();
			test_swap_bytes_helper(input_val, expected);
		}
	}
}
