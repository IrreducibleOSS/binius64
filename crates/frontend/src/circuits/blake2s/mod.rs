//! Blake2s hash function circuit implementation
//!
//! Blake2s is a cryptographic hash function optimized for 32-bit platforms,
//! producing digests from 1 to 32 bytes. This implementation follows RFC 7693
//! and supports variable-length messages with unkeyed hashing.
//!
//! ## RFC 7693 Compliance
//!
//! This implementation is fully compliant with RFC 7693 for the core Blake2s-256
//! hash function. It correctly implements the compression function, G mixing
//! function, and message scheduling as specified.
//!
//! ## Excluded Features
//!
//! This circuit implementation intentionally excludes the following optional
//! features from RFC 7693:
//!
//! - **Keyed hashing (MAC mode)**: Not supported. Use for hash verification only.
//! - **Salt parameter**: The 8-byte salt field is not implemented.
//! - **Personalization parameter**: The 8-byte personalization field is not implemented.
//! - **Tree hashing mode**: Only sequential mode is supported.
//! - **Variable output length**: Fixed at 256 bits (32 bytes).
//! - **Message size limitation**: Messages are limited to < 4GiB (2^32 bytes) as the high counter
//!   word (t_hi) is always zero. This is sufficient for most ZK circuit applications.
//!
//! These exclusions are appropriate for a ZK circuit focused on hash verification
//! rather than general-purpose hashing.
//!
//! # Algorithm Overview
//!
//! Blake2s processes messages in 512-bit (64-byte) blocks using a compression
//! function based on a modified ChaCha cipher. Each block undergoes 10 rounds
//! of mixing operations, where each round applies 8 G-function calls that
//! mix the internal state with message words.
//!
//! # Circuit Design
//!
//! This circuit verifies that a given message produces a specific Blake2s digest.
//! It handles variable-length messages by conditionally processing blocks based
//! on the actual message length, supporting messages up to a configured maximum.

mod constants;
#[cfg(test)]
mod test_vectors;
#[cfg(test)]
mod tests;

use binius_core::word::Word;
use constants::{IV, SIGMA};

use crate::compiler::{CircuitBuilder, Wire, circuit::WitnessFiller};

/// Blake2s G mixing function - the core cryptographic primitive.
///
/// The G function is the heart of Blake2s, providing confusion and diffusion
/// through a series of additions, XORs, and rotations. It operates on four
/// 32-bit state words (a, b, c, d) and two message words (x, y), mixing them
/// together in a way that ensures every bit of input affects every bit of output.
///
/// # Algorithm (RFC 7693 Section 3.1)
///
/// The function performs 8 operations in 4 stages:
/// 1. Mix a with b and first message word x, then rotate d
/// 2. Mix c with the rotated d, then rotate b
/// 3. Mix a with b and second message word y, then rotate d again
/// 4. Mix c with the rotated d, then rotate b again
///
/// The rotation amounts (16, 12, 8, 7) are carefully chosen to provide
/// good diffusion properties on 32-bit architectures.
///
/// # Constraint Cost
/// - 4x 32-bit additions (iadd_32): 8 AND constraints
/// - 4x 32-bit rotations (rotr_32): 4 AND constraints
/// - 4x XOR operations (bxor): FREE (0 constraints)
/// - **Total: 12 AND constraints per G-function call**
///
/// Since we call G 8 times per round and have 10 rounds, the total
/// cost for all G operations is 8 × 10 × 12 = 960 AND constraints.
pub fn g_function(
	builder: &mut CircuitBuilder,
	mut a: Wire,
	mut b: Wire,
	mut c: Wire,
	mut d: Wire,
	x: Wire,
	y: Wire,
) -> (Wire, Wire, Wire, Wire) {
	// ---- Stage 1: First message word mixing
	// a := a + b + x
	// d := (d ⊕ a) >>> 16
	a = builder.iadd_32(a, b);
	a = builder.iadd_32(a, x);
	d = builder.bxor(d, a); // XOR is free
	d = builder.rotr_32(d, 16);

	// ---- Stage 2: First diagonal mixing
	// c := c + d
	// b := (b ⊕ c) >>> 12
	c = builder.iadd_32(c, d);
	b = builder.bxor(b, c); // XOR is free
	b = builder.rotr_32(b, 12);

	// ---- Stage 3: Second message word mixing
	// a := a + b + y
	// d := (d ⊕ a) >>> 8
	a = builder.iadd_32(a, b);
	a = builder.iadd_32(a, y);
	d = builder.bxor(d, a); // XOR is free
	d = builder.rotr_32(d, 8);

	// ---- Stage 4: Second diagonal mixing
	// c := c + d
	// b := (b ⊕ c) >>> 7
	c = builder.iadd_32(c, d);
	b = builder.bxor(b, c); // XOR is free
	b = builder.rotr_32(b, 7);

	(a, b, c, d)
}

/// Blake2s compression function circuit.
///
/// This implements the core compression function F that processes a single
/// 64-byte message block and updates the internal hash state. The function
/// takes the current hash state, message block, byte counter, and finalization
/// flag as inputs.
///
/// # Algorithm (RFC 7693 Section 3.2)
///
/// 1. **Initialize working vector**: Combine hash state h with IV constants
/// 2. **Mix counter and flags**: XOR the counter t and finalization flag f into v[12..15]
/// 3. **Apply rounds**: Perform 10 rounds of mixing using the G function
/// 4. **Finalize**: XOR the working vector halves back into the hash state
///
/// # Circuit Design Notes
///
/// - All operations are performed on 32-bit words using Binius64 constraints
/// - The counter `t` tracks total bytes processed (including current block)
/// - The `last` flag indicates if this is the final block (sets f=-1)
/// - Message padding is handled externally before calling this function
///
/// # Constraint Cost Analysis
///
/// - G function calls: 8 × 10 × 12 = 960 AND constraints
/// - Counter operations: 2 AND constraints (for lo/hi counter mixing)
/// - State finalization: 16 XOR operations (FREE)
/// - **Total per compression: ~962 AND constraints**
pub fn blake2s_compress(
	builder: &mut CircuitBuilder,
	h: &[Wire; 8],  // Current hash state
	m: &[Wire; 16], // Message block (16 × 32-bit words = 64 bytes)
	t_lo: Wire,     // Low 32 bits of byte counter
	t_hi: Wire,     // High 32 bits of byte counter
	last: Wire,     // Finalization flag (0 or 0xFFFFFFFF)
) -> [Wire; 8] {
	// Initialize working vector v[0..15]
	let mut v = [builder.add_constant(Word(0)); 16];

	// First half from state: v[0..7] = h[0..7]
	v[0..8].copy_from_slice(h);

	// Second half from IV: v[8..15] = IV[0..7]
	for i in 0..8 {
		v[8 + i] = builder.add_constant(Word(IV[i] as u64));
	}

	// Mix in the counter and finalization flag
	// v[12] ^= t_lo (low 32 bits of byte counter)
	// v[13] ^= t_hi (high 32 bits of byte counter)
	// v[14] ^= f0 (first finalization word, always 0xFFFFFFFF if last block)
	// v[15] ^= f1 (second finalization word, always 0 for Blake2s)
	v[12] = builder.bxor(v[12], t_lo);
	v[13] = builder.bxor(v[13], t_hi);
	v[14] = builder.bxor(v[14], last); // last is 0xFFFFFFFF if final block

	// 10 rounds of G function mixing
	for round in 0..10 {
		// Column step: Apply G to columns (indices 0,4,8,12), (1,5,9,13), etc.
		let (v0, v4, v8, v12) =
			g_function(builder, v[0], v[4], v[8], v[12], m[SIGMA[round][0]], m[SIGMA[round][1]]);
		v[0] = v0;
		v[4] = v4;
		v[8] = v8;
		v[12] = v12;

		let (v1, v5, v9, v13) =
			g_function(builder, v[1], v[5], v[9], v[13], m[SIGMA[round][2]], m[SIGMA[round][3]]);
		v[1] = v1;
		v[5] = v5;
		v[9] = v9;
		v[13] = v13;

		let (v2, v6, v10, v14) =
			g_function(builder, v[2], v[6], v[10], v[14], m[SIGMA[round][4]], m[SIGMA[round][5]]);
		v[2] = v2;
		v[6] = v6;
		v[10] = v10;
		v[14] = v14;

		let (v3, v7, v11, v15) =
			g_function(builder, v[3], v[7], v[11], v[15], m[SIGMA[round][6]], m[SIGMA[round][7]]);
		v[3] = v3;
		v[7] = v7;
		v[11] = v11;
		v[15] = v15;

		// Diagonal step: Apply G to diagonals
		let (v0, v5, v10, v15) =
			g_function(builder, v[0], v[5], v[10], v[15], m[SIGMA[round][8]], m[SIGMA[round][9]]);
		v[0] = v0;
		v[5] = v5;
		v[10] = v10;
		v[15] = v15;

		let (v1, v6, v11, v12) =
			g_function(builder, v[1], v[6], v[11], v[12], m[SIGMA[round][10]], m[SIGMA[round][11]]);
		v[1] = v1;
		v[6] = v6;
		v[11] = v11;
		v[12] = v12;

		let (v2, v7, v8, v13) =
			g_function(builder, v[2], v[7], v[8], v[13], m[SIGMA[round][12]], m[SIGMA[round][13]]);
		v[2] = v2;
		v[7] = v7;
		v[8] = v8;
		v[13] = v13;

		let (v3, v4, v9, v14) =
			g_function(builder, v[3], v[4], v[9], v[14], m[SIGMA[round][14]], m[SIGMA[round][15]]);
		v[3] = v3;
		v[4] = v4;
		v[9] = v9;
		v[14] = v14;
	}

	// Finalization: h' = h ^ v[0..7] ^ v[8..15]
	let mut h_new = [builder.add_constant(Word(0)); 8];
	for i in 0..8 {
		h_new[i] = builder.bxor(h[i], v[i]);
		h_new[i] = builder.bxor(h_new[i], v[8 + i]);
	}

	h_new
}

/// Blake2s hash function circuit for variable-length messages.
///
/// This struct represents a complete Blake2s circuit that can verify
/// a message of variable length (up to `max_bytes`) produces a specific
/// 256-bit digest. The circuit handles message padding and block processing
/// according to RFC 7693.
///
/// # Circuit Structure
///
/// 1. **Message Input**: Variable-length byte array up to `max_bytes`
/// 2. **Length Input**: Actual message length in bytes
/// 3. **Processing**: Conditionally process blocks based on actual length
/// 4. **Output**: 256-bit digest (8 × 32-bit words)
///
/// # Design Decisions
///
/// - Supports variable-length messages through conditional block processing
/// - Pads messages to 64-byte blocks as per Blake2s specification
/// - Uses multiplexers to handle variable-length logic efficiently
/// - Optimized for messages up to a few hundred bytes
pub struct Blake2s {
	/// Maximum message size in bytes this circuit supports
	pub max_bytes: usize,
	/// Witness wires for the input message bytes
	pub message: Vec<Wire>,
	/// Witness wire for the actual message length
	pub length: Wire,
	/// Witness wires for the expected 256-bit digest (8 × 32-bit words)
	pub digest: [Wire; 8],
}

impl Blake2s {
	/// Create a new Blake2s circuit with witness variables.
	///
	/// This creates a circuit that can verify messages up to `max_bytes` in length.
	/// The actual message length is provided as a witness value at proving time.
	///
	/// # Arguments
	///
	/// * `builder` - Circuit builder to add constraints to
	/// * `max_bytes` - Maximum message size this circuit will support
	///
	/// # Returns
	///
	/// A Blake2s struct with witness wires for message, length, and digest
	pub fn new_witness(builder: &mut CircuitBuilder, max_bytes: usize) -> Self {
		assert!(max_bytes > 0, "max_bytes must be positive");

		// Create witness wires
		let message: Vec<Wire> = (0..max_bytes).map(|_| builder.add_witness()).collect();
		let length = builder.add_witness();
		let digest = std::array::from_fn(|_| builder.add_witness());

		// Build the circuit
		Self::build_circuit(builder, &message, length, digest, max_bytes);

		Self {
			max_bytes,
			message,
			length,
			digest,
		}
	}

	/// Build the Blake2s circuit constraints.
	///
	/// This constructs the circuit that verifies a variable-length message
	/// produces the expected Blake2s digest. The circuit handles:
	///
	/// 1. Message padding to 64-byte blocks
	/// 2. Conditional processing based on actual message length
	/// 3. Proper counter management for multi-block messages
	/// 4. Final block detection and processing
	fn build_circuit(
		builder: &mut CircuitBuilder,
		message: &[Wire],
		length: Wire,
		expected_digest: [Wire; 8],
		max_bytes: usize,
	) {
		// Calculate number of blocks needed for max size
		let max_blocks = max_bytes.div_ceil(64);
		let zero = builder.add_constant(Word(0));

		// SOUNDNESS: Enforce zero-padding constraint for RFC 7693 compliance
		// The Blake2s specification requires that all message bytes beyond the actual
		// message length must be zero. Without this constraint, a malicious prover
		// could provide non-zero bytes beyond `length` and still produce a valid proof,
		// violating the standard.
		//
		// For each byte position i in the message array:
		// - If i < length: byte can be any value (actual message data)
		// - If i >= length: byte MUST be zero (padding)
		for (i, &byte_wire) in message.iter().enumerate() {
			let index_wire = builder.add_constant(Word(i as u64));
			// Check if this index is beyond the actual message length
			// is_within_msg = (i < length) returns all-1s if true, all-0s if false
			let is_within_msg = builder.icmp_ult(index_wire, length);
			// If this is a padding byte (i >= length), it must be zero
			builder.assert_zero(
				"blake2s.zero_padding",
				builder.select(is_within_msg, zero, byte_wire),
			);
		}

		// Initialize hash state with Blake2s-256 parameters
		// h[0] = IV[0] ^ 0x01010020 (param block: digest_length=32, fanout=1, depth=1)
		let init_state = [
			builder.add_constant_64((IV[0] ^ 0x01010020) as u64),
			builder.add_constant_64(IV[1] as u64),
			builder.add_constant_64(IV[2] as u64),
			builder.add_constant_64(IV[3] as u64),
			builder.add_constant_64(IV[4] as u64),
			builder.add_constant_64(IV[5] as u64),
			builder.add_constant_64(IV[6] as u64),
			builder.add_constant_64(IV[7] as u64),
		];

		// Accumulator for the final digest (using masking)
		let mut final_digest_accumulator = [zero; 8];

		// Process each block and accumulate the correct digest
		let mut h = init_state;

		// Process each block - all blocks are processed but with appropriate padding
		for block_idx in 0..max_blocks {
			// Calculate byte offset for this block
			let block_start = block_idx * 64;

			// Prepare message block with proper padding
			let mut m = [builder.add_constant(Word(0)); 16];

			// Fill message words from input bytes
			for word_idx in 0..16 {
				let byte_offset = block_start + word_idx * 4;

				// Combine 4 bytes into a 32-bit word (little-endian)
				let mut word = builder.add_constant(Word(0));

				for byte_idx in 0..4 {
					let global_byte_idx = byte_offset + byte_idx;
					if global_byte_idx < max_bytes {
						// Get the byte wire (or zero if beyond message length)
						let byte_wire = if global_byte_idx < message.len() {
							message[global_byte_idx]
						} else {
							builder.add_constant(Word(0))
						};

						// Shift byte to correct position for little-endian encoding
						let shifted = if byte_idx == 0 {
							byte_wire
						} else {
							builder.shl(byte_wire, (byte_idx * 8) as u32)
						};

						word = builder.bxor(word, shifted);
					}
				}

				m[word_idx] = word;
			}

			// Determine if this block is in the valid range and if it's the final block
			let block_start = builder.add_constant(Word((block_idx * 64) as u64));
			let block_end = builder.add_constant(Word(((block_idx + 1) * 64) as u64));

			// Check if length > block_start (block is valid)
			let ge_start = if block_idx == 0 {
				builder.add_constant(Word::ALL_ONE) // First block always valid
			} else {
				builder.icmp_ult(block_start, length)
			};

			// Check if length <= block_end (this is the last block)
			// For exact block boundaries like 128 bytes, block 1 ends at 128 and should be final
			// length <= block_end is equivalent to NOT(block_end < length)
			let le_end = builder.bnot(builder.icmp_ult(block_end, length));

			// This block is the final block if both conditions are true
			let is_final_block = builder.band(ge_start, le_end);

			// Calculate counter and flag values using conditional masking
			// Counter: if final, use actual length; otherwise use block boundary
			let block_counter = builder.add_constant(Word(((block_idx + 1) * 64) as u64));

			// Use select for counter value
			let t_lo = builder.select(is_final_block, length, block_counter);
			// t_hi is always zero (see message size limitation in module documentation)
			let t_hi = zero;

			// Finalization flag: use select for conditional flag
			let flag_value = builder.add_constant(Word(0xFFFFFFFF));
			let last_flag = builder.select(is_final_block, flag_value, zero);

			// Process the block
			h = blake2s_compress(builder, &h, &m, t_lo, t_hi, last_flag);

			// Accumulate this state into final digest if it's the final block
			// Using masking: only XOR in the state if this is the final block
			for i in 0..8 {
				let masked_state = builder.select(is_final_block, h[i], zero);
				final_digest_accumulator[i] =
					builder.bxor(final_digest_accumulator[i], masked_state);
			}
		}

		// Assert that accumulated digest matches expected
		for i in 0..8 {
			builder.assert_eq("digest_match", final_digest_accumulator[i], expected_digest[i]);
		}
	}

	/// Populate the message witness data.
	///
	/// # Arguments
	///
	/// * `witness` - Witness filler to populate
	/// * `message` - The message bytes to hash
	pub fn populate_message(&self, witness: &mut WitnessFiller, message: &[u8]) {
		assert!(
			message.len() <= self.max_bytes,
			"Message length {} exceeds maximum {}",
			message.len(),
			self.max_bytes
		);

		// Set message bytes
		for (i, &byte) in message.iter().enumerate() {
			witness[self.message[i]] = Word(byte as u64);
		}

		// Pad remaining bytes with zeros
		for i in message.len()..self.max_bytes {
			witness[self.message[i]] = Word(0);
		}

		// Set actual length
		witness[self.length] = Word(message.len() as u64);
	}

	/// Populate the expected digest witness data.
	///
	/// # Arguments
	///
	/// * `witness` - Witness filler to populate
	/// * `digest` - The expected 32-byte Blake2s digest
	pub fn populate_digest(&self, witness: &mut WitnessFiller, digest: &[u8; 32]) {
		// Convert digest bytes to 8 × 32-bit words (little-endian)
		for i in 0..8 {
			let word_bytes = &digest[i * 4..(i + 1) * 4];
			let word = u32::from_le_bytes(word_bytes.try_into().unwrap());
			witness[self.digest[i]] = Word(word as u64);
		}
	}
}
