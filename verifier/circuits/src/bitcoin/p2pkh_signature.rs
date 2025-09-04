// Copyright 2025 Irreducible Inc.

use binius_core::word::Word;
use binius_frontend::compiler::{CircuitBuilder, Wire};

use crate::bignum::BigUint;

/// Compresses a secp256k1 public key from uncompressed (x, y) format to compressed format.
///
/// Bitcoin uses compressed public keys which are 33 bytes instead of 65 bytes:
/// - Uncompressed: \[0x04\] || x (32 bytes) || y (32 bytes) = 65 bytes
/// - Compressed: \[0x02 or 0x03\] || x (32 bytes) = 33 bytes
///
/// The prefix byte indicates the parity of the y-coordinate:
/// - 0x02 if y is even (LSB = 0)
/// - 0x03 if y is odd (LSB = 1)
///
/// # Arguments
/// * `builder` - Circuit builder for constructing constraints
/// * `x` - x-coordinate of the public key (32 bytes, 4 limbs)
/// * `y` - y-coordinate of the public key (32 bytes, 4 limbs)
///
/// # Returns
/// * `Vec<Wire>` - Compressed public key as 33 bytes suitable for sha256_fixed input. Each wire
///   contains 4 bytes (32-bit word) with high 32 bits zeroed.
///
/// # Panics
/// * If x or y don't have exactly 4 limbs (256 bits)
pub fn compress_pubkey(builder: &CircuitBuilder, x: &BigUint, y: &BigUint) -> Vec<Wire> {
	assert_eq!(x.limbs.len(), 4, "x-coordinate must be exactly 4 limbs (256 bits)");
	assert_eq!(y.limbs.len(), 4, "y-coordinate must be exactly 4 limbs (256 bits)");

	// Check if y is even or odd by examining the LSB of the least significant limb
	let y_is_odd = builder.shl(y.limbs[0], 63);

	// Create prefix: 0x02 if y is even, 0x03 if y is odd
	let prefix_even = builder.add_constant(Word::from_u64(0x02));
	let prefix_odd = builder.add_constant(Word::from_u64(0x03));
	let prefix_byte = builder.select(y_is_odd, prefix_odd, prefix_even);

	// We need to produce 9 words (33 bytes) for sha256_fixed
	// Each word represents 4 bytes packed in big-endian format
	let zero = builder.add_constant(Word::ZERO);
	let mut compressed_words = Vec::with_capacity(9);

	for word_idx in 0..9 {
		let mut word = zero;

		for byte_pos in 0..4 {
			let global_byte_idx = word_idx * 4 + byte_pos;

			if global_byte_idx == 0 {
				// First byte is the prefix
				word = builder.bxor(word, builder.shl(prefix_byte, (3 - byte_pos) * 8));
			} else if global_byte_idx <= 32 {
				// Bytes 1-32 are x coordinate bytes in big-endian order
				let x_byte_idx = global_byte_idx - 1; // 0-indexed into x coordinate

				// For big-endian output, we want:
				// x_byte_idx 0 should give us x_bytes[0] (the first byte of the big-endian
				// representation) x_bytes[0] corresponds to the MSB, which is at position 31 in
				// little-endian byte ordering x_bytes[31] corresponds to the LSB, which is at
				// position 0 in little-endian byte ordering

				// So x_byte_idx 0 -> byte position 31 in LE
				// x_byte_idx 31 -> byte position 0 in LE
				let le_byte_idx = x_byte_idx; // This is the direct mapping since we defined x_bytes in BE order
				let limb_idx = le_byte_idx / 8;
				let byte_in_limb = le_byte_idx % 8;

				let byte_val = extract_byte_from_limb(
					builder,
					x.limbs[limb_idx as usize],
					byte_in_limb as usize,
				);
				word = builder.bxor(word, builder.shl(byte_val, (3 - byte_pos) * 8));
			}
			// global_byte_idx > 32: leave as zero (padding)
		}

		compressed_words.push(word);
	}

	compressed_words
}

/// Extract a specific byte from a 64-bit limb
/// byte_idx: 0 = LSB, 7 = MSB
fn extract_byte_from_limb(builder: &CircuitBuilder, limb: Wire, byte_idx: usize) -> Wire {
	assert!(byte_idx < 8, "byte_idx must be < 8");
	let shift = byte_idx * 8;
	let shifted = builder.shr(limb, shift as u32);
	builder.band(shifted, builder.add_constant(Word::from_u64(0xFF)))
}

#[cfg(test)]
mod tests {
	use binius_core::{verify::verify_constraints, word::Word};

	use super::*;

	fn test_compress_helper(x_bytes: [u8; 32], y_bytes: [u8; 32], expected_compressed: [u8; 33]) {
		let builder = CircuitBuilder::new();

		// Convert byte arrays to BigUint limbs (little-endian)
		let x = BigUint::new_witness(&builder, 4);
		let y = BigUint::new_witness(&builder, 4);

		// Expected compressed output wires for verification
		let expected_words: Vec<Wire> = (0..9).map(|_| builder.add_witness()).collect();

		// Call compress function
		let compressed = compress_pubkey(&builder, &x, &y);

		// Assert equality with expected result
		for i in 0..9 {
			builder.assert_eq(format!("compressed[{}]", i), compressed[i], expected_words[i]);
		}

		let circuit = builder.build();
		let mut w = circuit.new_witness_filler();

		// Populate x and y coordinates
		let x_limbs: [u64; 4] = [
			u64::from_le_bytes([
				x_bytes[0], x_bytes[1], x_bytes[2], x_bytes[3], x_bytes[4], x_bytes[5], x_bytes[6],
				x_bytes[7],
			]),
			u64::from_le_bytes([
				x_bytes[8],
				x_bytes[9],
				x_bytes[10],
				x_bytes[11],
				x_bytes[12],
				x_bytes[13],
				x_bytes[14],
				x_bytes[15],
			]),
			u64::from_le_bytes([
				x_bytes[16],
				x_bytes[17],
				x_bytes[18],
				x_bytes[19],
				x_bytes[20],
				x_bytes[21],
				x_bytes[22],
				x_bytes[23],
			]),
			u64::from_le_bytes([
				x_bytes[24],
				x_bytes[25],
				x_bytes[26],
				x_bytes[27],
				x_bytes[28],
				x_bytes[29],
				x_bytes[30],
				x_bytes[31],
			]),
		];

		let y_limbs: [u64; 4] = [
			u64::from_le_bytes([
				y_bytes[0], y_bytes[1], y_bytes[2], y_bytes[3], y_bytes[4], y_bytes[5], y_bytes[6],
				y_bytes[7],
			]),
			u64::from_le_bytes([
				y_bytes[8],
				y_bytes[9],
				y_bytes[10],
				y_bytes[11],
				y_bytes[12],
				y_bytes[13],
				y_bytes[14],
				y_bytes[15],
			]),
			u64::from_le_bytes([
				y_bytes[16],
				y_bytes[17],
				y_bytes[18],
				y_bytes[19],
				y_bytes[20],
				y_bytes[21],
				y_bytes[22],
				y_bytes[23],
			]),
			u64::from_le_bytes([
				y_bytes[24],
				y_bytes[25],
				y_bytes[26],
				y_bytes[27],
				y_bytes[28],
				y_bytes[29],
				y_bytes[30],
				y_bytes[31],
			]),
		];

		x.populate_limbs(&mut w, &x_limbs);
		y.populate_limbs(&mut w, &y_limbs);

		// Pack expected compressed bytes into 32-bit words for comparison
		let mut expected_word_values = [0u32; 9];
		for i in 0..9 {
			let word_start = i * 4;
			if word_start < 33 {
				let bytes_in_word = std::cmp::min(4, 33 - word_start);
				let mut word = 0u32;
				for j in 0..bytes_in_word {
					word |= (expected_compressed[word_start + j] as u32) << (24 - j * 8);
				}
				expected_word_values[i] = word;
			}
		}

		for i in 0..9 {
			w[expected_words[i]] = Word::from_u64(expected_word_values[i] as u64);
		}

		circuit.populate_wire_witness(&mut w).unwrap();
		verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_compress_simple() {
		// Simple test with known values to debug byte ordering
		let x_bytes = [
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
			0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
			0x1D, 0x1E, 0x1F, 0x20,
		];

		let y_bytes = [
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, // Even y (LSB = 0x02 which is even)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		];

		// Expected compressed: prefix 0x02 + x bytes in big-endian
		let expected_compressed = [
			0x02, // prefix for even y
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
			0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
			0x1D, 0x1E, 0x1F, 0x20,
		];

		test_compress_helper(x_bytes, y_bytes, expected_compressed);
	}

	#[test]
	fn test_compress_odd_y() {
		// Point with odd y coordinate
		let x_bytes = [
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11,
		];

		let y_bytes = [
			0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, // LSB is odd
			0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
			0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		];

		// Expected compressed format: 0x03 prefix + x coordinate (y is odd)
		let expected_compressed = [
			0x03, // prefix for odd y
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11,
		];

		test_compress_helper(x_bytes, y_bytes, expected_compressed);
	}

	#[test]
	fn test_compress_even_y() {
		// Point with even y coordinate
		let x_bytes = [
			0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0xAA,
		];

		let y_bytes = [
			0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // LSB is even
			0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
			0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
		];

		// Expected compressed format: 0x02 prefix + x coordinate (y is even)
		let expected_compressed = [
			0x02, // prefix for even y
			0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA, 0xAA, 0xAA,
		];

		test_compress_helper(x_bytes, y_bytes, expected_compressed);
	}
}
