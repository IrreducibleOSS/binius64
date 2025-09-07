// Copyright 2025 Irreducible Inc.
//! BLAKE2b circuit implementation for Binius64
//!
//! This module implements BLAKE2b as a zero-knowledge circuit using the Binius64
//! constraint system. It follows the RFC 7693 specification.

use binius_core::word::Word;

use super::constants::{BLOCK_BYTES, IV, ROUNDS, SIGMA};
use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Maximum number of blocks the circuit can process (16KB max message)
pub const MAX_BLOCKS: usize = 128;

/// BLAKE2b circuit with fixed maximum allocation
pub struct Blake2bCircuit {
	/// Message blocks (16 words of 64 bits each per block)
	pub message_blocks: [[Wire; 16]; MAX_BLOCKS],

	/// Number of blocks actually used (0 to MAX_BLOCKS)
	pub num_blocks: Wire,

	/// Total message length in bytes
	pub message_length: Wire,

	/// Initial hash state (can be keyed)
	pub initial_state: [Wire; 8],

	/// Final hash output
	pub output: [Wire; 8],
}

impl Blake2bCircuit {
	/// Create a new BLAKE2b circuit with standard 64-byte output
	pub fn new(builder: &CircuitBuilder) -> Self {
		Self::new_with_params(builder, 64)
	}

	/// Create a new BLAKE2b circuit with specified output length
	pub fn new_with_params(builder: &CircuitBuilder, outlen: usize) -> Self {
		assert!(outlen > 0 && outlen <= 64, "Output length must be 1-64 bytes");

		// Allocate message blocks
		let message_blocks =
			core::array::from_fn(|_| core::array::from_fn(|_| builder.add_witness()));

		let num_blocks = builder.add_witness();
		let message_length = builder.add_witness();

		// Initialize state with IVs XORed with parameter block
		// Parameter block: 0x0101kknn where nn=outlen, kk=keylen (0), fanout=depth=1
		let param_block = 0x01010000 | (outlen as u64);

		let initial_state = core::array::from_fn(|i| {
			if i == 0 {
				builder.add_constant(Word(IV[i] ^ param_block))
			} else {
				builder.add_constant(Word(IV[i]))
			}
		});

		// Process the message
		let mut h = initial_state;
		process_message(builder, &message_blocks, num_blocks, message_length, &mut h);

		let output = h;

		Self {
			message_blocks,
			num_blocks,
			message_length,
			initial_state,
			output,
		}
	}

	/// Populate the message data into the witness
	pub fn populate_message(&self, w: &mut WitnessFiller, message: &[u8]) {
		let blocks = Self::prepare_message_blocks(message);

		// Populate message blocks
		for (block_idx, block) in blocks.iter().enumerate() {
			for (word_idx, &word) in block.iter().enumerate() {
				w[self.message_blocks[block_idx][word_idx]] = Word(word);
			}
		}
		// Unused blocks are automatically initialized to zero
	}

	/// Populate the message length into the witness
	pub fn populate_length(&self, w: &mut WitnessFiller, message: &[u8]) {
		w[self.message_length] = Word(message.len() as u64);
		w[self.num_blocks] = Word(Self::calculate_num_blocks(message.len()));
	}

	/// Populate the expected digest output for verification (if needed)
	pub fn populate_digest(&self, w: &mut WitnessFiller, digest: &[u8; 64]) {
		// Note: The output is computed by the circuit, not populated directly
		// This method is provided for completeness but typically isn't needed
		// as the circuit computes the digest from the message
		for (i, &byte) in digest.iter().enumerate() {
			let word_idx = i / 8;
			let byte_idx = i % 8;
			let current = w[self.output[word_idx]].0;
			let mask = !(0xFFu64 << (byte_idx * 8));
			let new_val = (current & mask) | ((byte as u64) << (byte_idx * 8));
			w[self.output[word_idx]] = Word(new_val);
		}
	}

	/// Helper to prepare message blocks from raw bytes
	fn prepare_message_blocks(message: &[u8]) -> Vec<[u64; 16]> {
		let mut blocks = Vec::new();
		let mut offset = 0;

		// Process all complete blocks except the last one
		while offset + 128 < message.len() {
			let mut block = [0u64; 16];

			// Copy 128 bytes to block (16 words × 8 bytes)
			for i in 0..128 {
				let byte_val = message[offset + i];
				let word_idx = i / 8;
				let byte_idx = i % 8;
				block[word_idx] |= (byte_val as u64) << (byte_idx * 8);
			}

			blocks.push(block);
			offset += 128;
		}

		// Handle the final block (always exists, may be partial or full)
		// This includes the case where we have exactly 128*n bytes
		{
			let mut block = [0u64; 16];
			let remaining = message.len() - offset;

			// Copy remaining bytes
			for i in 0..remaining {
				let byte_val = message[offset + i];
				let word_idx = i / 8;
				let byte_idx = i % 8;
				block[word_idx] |= (byte_val as u64) << (byte_idx * 8);
			}

			blocks.push(block);
		}

		blocks
	}

	/// Calculate the number of blocks needed for a message
	fn calculate_num_blocks(message_len: usize) -> u64 {
		if message_len == 0 {
			1
		} else {
			message_len.div_ceil(128) as u64
		}
	}
}

/// Process variable-length message with masking
fn process_message(
	builder: &CircuitBuilder,
	message_blocks: &[[Wire; 16]; MAX_BLOCKS],
	num_blocks: Wire,
	message_length: Wire,
	h: &mut [Wire; 8],
) {
	let zero = builder.add_constant(Word::ZERO);

	for i in 0..MAX_BLOCKS {
		// Check if this block is active
		let block_index = builder.add_constant(Word(i as u64));
		let is_active = builder.icmp_ult(block_index, num_blocks);

		// Calculate byte counter for this block
		// For block i: if i < num_blocks-1, counter = (i+1) * 128
		//             if i == num_blocks-1, counter = message_length
		let next_block_index = builder.add_constant(Word((i + 1) as u64));
		let is_last = builder.icmp_eq(next_block_index, num_blocks);

		let block_counter_normal = builder.add_constant(Word(((i + 1) * BLOCK_BYTES) as u64));
		let block_counter = builder.select(is_last, message_length, block_counter_normal);

		// Save current state
		let h_before = *h;

		// Compress this block (will be no-op if not active due to masking)
		compress(builder, h, &message_blocks[i], block_counter, zero, is_last);

		// Select between updated and original state based on is_active
		for j in 0..8 {
			h[j] = builder.select(is_active, h[j], h_before[j]);
		}
	}
}

/// BLAKE2b compression function
pub fn compress(
	builder: &CircuitBuilder,
	h: &mut [Wire; 8],
	m: &[Wire; 16],
	t_low: Wire,
	t_high: Wire,
	last_block_flag: Wire,
) {
	// Initialize working vector
	let mut v = [builder.add_constant(Word::ZERO); 16];

	// v[0..8] = h[0..8]
	#[allow(clippy::manual_memcpy)]
	for i in 0..8 {
		v[i] = h[i];
	}

	// v[8..16] = IV[0..8]
	for i in 0..8 {
		v[i + 8] = builder.add_constant(Word(IV[i]));
	}

	// Mix in counter
	v[12] = builder.bxor(v[12], t_low);
	v[13] = builder.bxor(v[13], t_high);

	// Conditionally invert v[14] for last block
	v[14] = builder.select(last_block_flag, builder.bnot(v[14]), v[14]);

	// 12 rounds of mixing
	for round in 0..ROUNDS {
		// Column step
		g_mixing(builder, &mut v, 0, 4, 8, 12, m[SIGMA[round][0]], m[SIGMA[round][1]]);
		g_mixing(builder, &mut v, 1, 5, 9, 13, m[SIGMA[round][2]], m[SIGMA[round][3]]);
		g_mixing(builder, &mut v, 2, 6, 10, 14, m[SIGMA[round][4]], m[SIGMA[round][5]]);
		g_mixing(builder, &mut v, 3, 7, 11, 15, m[SIGMA[round][6]], m[SIGMA[round][7]]);

		// Diagonal step
		g_mixing(builder, &mut v, 0, 5, 10, 15, m[SIGMA[round][8]], m[SIGMA[round][9]]);
		g_mixing(builder, &mut v, 1, 6, 11, 12, m[SIGMA[round][10]], m[SIGMA[round][11]]);
		g_mixing(builder, &mut v, 2, 7, 8, 13, m[SIGMA[round][12]], m[SIGMA[round][13]]);
		g_mixing(builder, &mut v, 3, 4, 9, 14, m[SIGMA[round][14]], m[SIGMA[round][15]]);
	}

	// Finalization: h[i] = h[i] XOR v[i] XOR v[i+8]
	for i in 0..8 {
		h[i] = builder.bxor_multi(&[h[i], v[i], v[i + 8]]);
	}
}

/// BLAKE2b G mixing function
///
/// This implements the core mixing operation:
/// ```text
/// a = a + b + x
/// d = rotr64(d ^ a, 32)
/// c = c + d
/// b = rotr64(b ^ c, 24)
/// a = a + b + y
/// d = rotr64(d ^ a, 16)
/// c = c + d
/// b = rotr64(b ^ c, 63)
/// ```
///
/// Cost: 8 AND constraints (4 additions × 2 constraints each)
#[allow(clippy::too_many_arguments)]
pub fn g_mixing(
	builder: &CircuitBuilder,
	v: &mut [Wire; 16],
	a: usize,
	b: usize,
	c: usize,
	d: usize,
	x: Wire,
	y: Wire,
) {
	let zero = builder.add_constant(Word::ZERO);

	// a = a + b + x (use separate additions without carry chaining)
	let (temp1, _) = builder.iadd_cin_cout(v[a], v[b], zero);
	let (v_a_new1, _) = builder.iadd_cin_cout(temp1, x, zero);
	v[a] = v_a_new1;

	// d = rotr64(d ^ a, 32)
	let xor1 = builder.bxor(v[d], v[a]);
	v[d] = builder.rotr(xor1, 32);

	// c = c + d
	let (v_c_new1, _) = builder.iadd_cin_cout(v[c], v[d], zero);
	v[c] = v_c_new1;

	// b = rotr64(b ^ c, 24)
	let xor2 = builder.bxor(v[b], v[c]);
	v[b] = builder.rotr(xor2, 24);

	// a = a + b + y (use separate additions without carry chaining)
	let (temp2, _) = builder.iadd_cin_cout(v[a], v[b], zero);
	let (v_a_new2, _) = builder.iadd_cin_cout(temp2, y, zero);
	v[a] = v_a_new2;

	// d = rotr64(d ^ a, 16)
	let xor3 = builder.bxor(v[d], v[a]);
	v[d] = builder.rotr(xor3, 16);

	// c = c + d
	let (v_c_new2, _) = builder.iadd_cin_cout(v[c], v[d], zero);
	v[c] = v_c_new2;

	// b = rotr64(b ^ c, 63)
	let xor4 = builder.bxor(v[b], v[c]);
	v[b] = builder.rotr(xor4, 63);
}

#[cfg(test)]
mod tests {
	use binius_core::{verify::verify_constraints, word::Word};

	use crate::{
		circuits::blake2b::{circuit::g_mixing, reference},
		compiler::CircuitBuilder,
	};

	/// Test the G mixing function with known values
	#[test]
	fn test_g_mixing_function() {
		let builder = CircuitBuilder::new();

		let mut v = core::array::from_fn(|_| builder.add_inout());
		let x = builder.add_inout();
		let y = builder.add_inout();

		// Expected outputs
		let expected: [_; 16] = core::array::from_fn(|_| builder.add_inout());

		// Save the initial wires before G mixing
		let v_initial = v;

		// Apply G mixing
		g_mixing(&builder, &mut v, 0, 4, 8, 12, x, y);

		// The g_mixing function has updated v[0], v[4], v[8], v[12] with new wires
		// Assert equality between the new values and expected
		for i in [0, 4, 8, 12] {
			builder.assert_eq(format!("v[{}]", i), v[i], expected[i]);
		}

		let circuit = builder.build();

		// Test with simple values
		let mut w = circuit.new_witness_filler();

		// Initial state (simple test values)
		let initial_v = [
			0x0000000000000001u64, // v[0]
			0x0000000000000002u64, // v[1]
			0x0000000000000003u64, // v[2]
			0x0000000000000004u64, // v[3]
			0x0000000000000005u64, // v[4]
			0x0000000000000006u64, // v[5]
			0x0000000000000007u64, // v[6]
			0x0000000000000008u64, // v[7]
			0x0000000000000009u64, // v[8]
			0x000000000000000Au64, // v[9]
			0x000000000000000Bu64, // v[10]
			0x000000000000000Cu64, // v[11]
			0x000000000000000Du64, // v[12]
			0x000000000000000Eu64, // v[13]
			0x000000000000000Fu64, // v[14]
			0x0000000000000010u64, // v[15]
		];

		let x_val = 0x123456789ABCDEFu64;
		let y_val = 0xFEDCBA9876543210u64;

		for i in 0..16 {
			w[v_initial[i]] = Word(initial_v[i]);
		}
		w[x] = Word(x_val);
		w[y] = Word(y_val);

		// Run reference G to get expected values
		let mut expected_v = initial_v;
		reference::g(&mut expected_v, 0, 4, 8, 12, x_val, y_val);

		for i in [0, 4, 8, 12] {
			w[expected[i]] = Word(expected_v[i]);
		}

		// Populate witness and verify constraints
		circuit.populate_wire_witness(&mut w).unwrap();

		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}
}
