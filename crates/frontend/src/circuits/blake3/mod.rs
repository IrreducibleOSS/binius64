//! Blake3 hash function implementation for Binius64
//!
//! This implementation supports variable-length inputs up to 16KB (16 chunks)
//! using a fixed-depth tree structure with validity masks.
//!
//! Based on the official Blake3 specification with adaptations for ZK circuits.
//!
//! # Algorithm Overview
//!
//! Blake3 processes input in 1024-byte chunks, each containing up to 16 blocks
//! of 64 bytes. For single-chunk inputs, the compression function applies
//! 7 rounds of mixing operations to produce the final hash.
//!
//! Reference: BLAKE3 specification (<https://github.com/BLAKE3-team/BLAKE3-specs>)
//! This implementation follows the 7-round variant for 128-bit security.
//!
//! # Wire Layout and Data Format
//!
//! The circuit uses different wire organizations for efficiency:
//!
//! | Component | Wire Format | Byte Order | Notes |
//! |-----------|-------------|------------|-------|
//! | Message input | 64-bit wires | Little-endian | 8 bytes per wire |
//! | Internal state | 32-bit values in 64-bit wires | Little-endian | Lower 32 bits used |
//! | Block words | 16×32-bit in 64-bit wires | Little-endian | For compression |
//! | Output hash | 4×64-bit wires | Little-endian | 32 bytes total |
//! | Chaining value | 8×32-bit in 64-bit wires | Little-endian | 32 bytes state |
//!
//! # Constraint Cost Analysis
//!
//! Per-operation constraint counts (OPTIMIZED):
//! - G-function: 20 AND (6 additions @ 2 AND, 4 rotations @ 1 AND, 4 XORs @ 0 AND, witness ops @ 4
//!   AND)
//! - Single round: 160 AND (8 G-functions × 20 AND)
//! - Full compression: 1120 AND (7 rounds × 160 AND)
//! - Tree parent node: 1120 AND (one compression)
//! - Chunk processing: ~1150 AND per 64-byte block
//!
//! Achieved 50% reduction from original 40 AND per G-function
pub mod compress;
pub mod constants;
pub mod g_function;
pub mod reference;
pub mod tree;

// Common utilities
pub mod common;

use binius_core::word::Word;

use crate::compiler::{circuit::WitnessFiller, CircuitBuilder, Wire};

/// Compute Blake3 hash for variable-length input
///
/// # Arguments
/// * `builder` - Circuit builder for constructing constraints
/// * `message` - Input message as 64-bit wires (8 bytes per wire)
/// * `actual_bytes` - Wire containing the actual message length in bytes
/// * `max_bytes` - Maximum message length (determines circuit structure)
///
/// # Returns
/// Blake3 hash as 4x64-bit wires (32 bytes total)
pub fn blake3_hash(
	builder: &mut CircuitBuilder,
	message: &[Wire],
	actual_bytes: Wire,
	max_bytes: usize,
) -> [Wire; 4] {
	// Initialize zero hashes for empty subtrees
	let zero_hashes = constants::ZeroHashes::new(builder);

	// Calculate actual number of chunks
	let actual_chunks = tree::calculate_chunk_count(builder, actual_bytes);

	// Convert message to 32-bit words for Blake3 processing
	let message_words = common::bytes_to_words(builder, message);

	// Process all chunks and build the tree
	let final_hash = if max_bytes <= constants::CHUNK_SIZE {
		// Single chunk case - simpler processing
		process_single_chunk(builder, &message_words, actual_bytes)
	} else {
		// Multi-chunk case - build full tree
		let tree_nodes = tree::build_fixed_tree(
			builder,
			&message_words,
			actual_bytes,
			actual_chunks,
			max_bytes,
			&zero_hashes,
		);

		// Select output based on actual chunk count
		tree::select_tree_output(builder, &tree_nodes, actual_chunks)
	};

	// Pack 32-bit words into 64-bit output wires
	common::pack_output(builder, &final_hash)
}

/// Process a single chunk (≤1024 bytes)
fn process_single_chunk(
	builder: &mut CircuitBuilder,
	message_words: &[Wire],
	actual_bytes: Wire,
) -> [Wire; 8] {
	// Initialize chaining value with IV
	let mut cv = [builder.add_constant_64(0); 8];
	for i in 0..8 {
		cv[i] = builder.add_constant_64(constants::IV[i] as u64);
	}

	// Process blocks within the chunk
	let num_blocks = message_words.len().div_ceil(16);
	let num_blocks = num_blocks.min(constants::BLOCKS_PER_CHUNK);

	for block_idx in 0..num_blocks {
		// Extract block data
		let mut block = [builder.add_constant_64(0); 16];
		let start = block_idx * 16;
		let end = ((block_idx + 1) * 16).min(message_words.len());

		if start < message_words.len() {
			#[allow(clippy::manual_memcpy)] // Wire arrays can't use copy_from_slice
			for i in 0..(end - start) {
				block[i] = message_words[start + i];
			}
		}

		// Calculate block flags
		let mut flags = builder.add_constant_64(0);

		// First block gets CHUNK_START
		if block_idx == 0 {
			flags = builder.bor(flags, builder.add_constant_64(constants::CHUNK_START as u64));
		}

		// Last block gets CHUNK_END and ROOT (for single chunk)
		if block_idx == num_blocks - 1 {
			flags = builder.bor(
				flags,
				builder.add_constant_64((constants::CHUNK_END | constants::ROOT) as u64),
			);
		}

		// Counter is always 0 for single chunk
		let counter = builder.add_constant_64(0);

		// Calculate block length (may be < 64 for last block)
		let block_start = builder.add_constant_64((block_idx * 64) as u64);
		let remaining = builder
			.isub_bin_bout(actual_bytes, block_start, builder.add_constant_64(0))
			.0;
		let is_partial = builder.icmp_ult(remaining, builder.add_constant_64(64));
		let block_len = builder.select(builder.add_constant_64(64), remaining, is_partial);

		// Compress block
		let output = compress::compress(builder, &cv, &block, counter, block_len, flags);

		// Update chaining value
		#[allow(clippy::manual_memcpy)] // Wire arrays can't use copy_from_slice
		for i in 0..8 {
			cv[i] = output[i];
		}
	}

	cv
}

/// Blake3 initialization vector (fractional parts of square roots of primes 2-19)
pub const IV: [u32; 8] = [
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Blake3 flag constants
pub const CHUNK_START: u32 = 1 << 0;
pub const CHUNK_END: u32 = 1 << 1;
pub const PARENT: u32 = 1 << 2;
pub const ROOT: u32 = 1 << 3;
pub const KEYED_HASH: u32 = 1 << 4;
pub const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
pub const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// Message schedule permutation for Blake3 (7 rounds)
pub const MSG_SCHEDULE: [[usize; 16]; 7] = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
	[3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
	[10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
	[12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
	[9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
	[11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Blake3 hash verifier circuit.
///
/// Validates that a message produces a specific Blake3 digest. The circuit
/// structure is fixed at compile time based on the maximum message length.
pub struct Blake3 {
	/// Maximum input length in bytes
	pub max_len: usize,
	/// Actual input length in bytes
	pub len: Wire,
	/// Input message as packed 64-bit words
	pub message: Vec<Wire>,
	/// Output hash (32 bytes as 4x64-bit words)
	pub output: [Wire; 4],
}

impl Blake3 {
	/// Creates a new Blake3 verifier circuit.
	///
	/// # Arguments
	/// * `builder` - Circuit builder for constructing constraints
	/// * `max_len` - Maximum message length in bytes (determines circuit size)
	/// * `len` - Wire containing the actual message length
	/// * `message` - Message wires (must have length = max_len/8 rounded up)
	///
	/// # Panics
	/// * If `max_len` is 0
	/// * If `message.len()` != ceil(max_len/8)
	///
	/// # Circuit Structure
	/// The circuit performs the following validations:
	/// 1. Ensures actual length <= max_len
	/// 2. Processes message in 64-byte blocks
	/// 3. Builds chunk tree for messages > 64 bytes
	/// 4. Computes Blake3 hash matching the output
	pub fn new(
		builder: &mut CircuitBuilder,
		max_len: usize,
		len: Wire,
		message: Vec<Wire>,
	) -> Self {
		// ---- Circuit construction overview
		//
		// This function builds a Blake3 circuit with the following structure:
		//
		// 1. Input validation and setup
		//    - Validate maximum length constraints
		//    - Ensure wire count matches expected size
		//
		// 2. Message format conversion
		//    - Convert 64-bit wires to 32-bit words for Blake3 processing
		//    - Extract low and high 32-bit parts from each wire
		//
		// 3. Processing strategy selection
		//    - 3a: Single-block processing (≤64 bytes)
		//    - 3b: Multi-block/chunk processing (>64 bytes)
		//
		// 4. Output packing
		//    - Combine 32-bit results into 64-bit output wires

		// ---- 1. Input validation and setup
		//
		// Blake3 requires positive message length for circuit construction.
		// The circuit structure is fixed at compile time based on max_len,
		// which determines how many blocks and chunks we need to process.
		assert!(max_len > 0, "Maximum length must be positive");
		assert_eq!(message.len(), max_len.div_ceil(8), "Message wire count mismatch");

		// ---- 2. Message format conversion
		//
		// Blake3 internally operates on 32-bit words (following the spec),
		// but our interface uses 64-bit wires for efficiency (8 bytes per wire).
		// We need to split each 64-bit wire into two 32-bit words.
		//
		// Wire format: wire = low_32 | (high_32 << 32)
		// Extraction process:
		// - Low word: wire & 0xFFFFFFFF
		// - High word: wire >> 32
		let mut message_words = Vec::new();
		for msg_wire in message.iter() {
			// Extract lower 32 bits: wire & 0xFFFFFFFF
			// Cost: 1 AND constraint for masking
			let low = builder.band(*msg_wire, builder.add_constant_64(0xFFFFFFFF));
			message_words.push(low);

			// Extract upper 32 bits: wire >> 32
			// Cost: 1 AND constraint for shift
			let high = builder.shr(*msg_wire, 32);
			message_words.push(high);
		}

		// ---- 3. Processing strategy selection
		//
		// Blake3 uses different processing strategies based on message size:
		// - Messages ≤64 bytes: Single block, direct compression
		// - Messages >64 bytes: Multiple blocks, chunk processing with tree structure

		// ---- 3a. Single-block processing (messages ≤ 64 bytes)
		//
		// Small messages fit entirely in one 64-byte block and don't require
		// chunking or tree construction. This is the simplest and most efficient
		// path for short inputs.
		if max_len <= 64 {
			// ---- 3a.1. Block preparation
			//
			// Create a 16-word (64-byte) block and fill it with message data.
			// Remaining positions are implicitly zero-padded.
			let mut block = [builder.add_constant_64(0); 16];

			// Fill block with available message words
			// Note: message_words.len() ≤ 16 for messages ≤ 64 bytes
			block
				.iter_mut()
				.take(16.min(message_words.len()))
				.zip(message_words.iter())
				.for_each(|(b, &m)| *b = m);

			// ---- 3a.2. Chaining value initialization
			//
			// Blake3 starts with a fixed initialization vector (IV) derived from
			// the fractional parts of the square roots of the first 8 primes.
			// This provides nothing-up-my-sleeve constants.
			let mut cv = [builder.add_constant_64(0); 8];
			for i in 0..8 {
				cv[i] = builder.add_constant_64(IV[i] as u64);
			}

			// ---- 3a.3. Flag configuration for single-block messages
			//
			// Single-block messages are special: they are simultaneously:
			// - CHUNK_START: First block of the chunk
			// - CHUNK_END: Last block of the chunk
			// - ROOT: Final output node (no tree needed)
			//
			// This combination tells the compression function to produce
			// the final hash directly without further processing.
			let flags = builder.add_constant_64((CHUNK_START | CHUNK_END | ROOT) as u64);

			// Block counter is 0 for the first (and only) block
			let counter = builder.add_constant_64(0);

			// Block length is the actual message length (may be < 64)
			let block_len = len;

			// ---- 3a.4. Compression function application
			//
			// Apply the 7-round Blake3 compression function.
			let hash_words = compress::compress(builder, &cv, &block, counter, block_len, flags);

			// ---- Output packing
			// Combine pairs of 32-bit words into 64-bit wires for output.
			// Each output wire = low_word | (high_word << 32)
			let computed_output = [
				builder.bor(hash_words[0], builder.shl(hash_words[1], 32)),
				builder.bor(hash_words[2], builder.shl(hash_words[3], 32)),
				builder.bor(hash_words[4], builder.shl(hash_words[5], 32)),
				builder.bor(hash_words[6], builder.shl(hash_words[7], 32)),
			];

			// Create witness wires and add equality constraints
			let output = [
				builder.add_witness(),
				builder.add_witness(),
				builder.add_witness(),
				builder.add_witness(),
			];

			// Add equality constraints between computed and expected output
			for i in 0..4 {
				builder.assert_eq(
					format!("blake3_output_match_{}", i),
					computed_output[i],
					output[i],
				);
			}

			Blake3 {
				max_len,
				len,
				message,
				output,
			}
		} else {
			// ---- 3b. Multi-block processing (messages > 64 bytes)
			//
			// Blake3 processes data in 1024-byte CHUNKS, each containing up to 16 BLOCKS.

			// Multi-block processing (messages > 64 bytes)
			// Blake3 processes data in 1024-byte chunks, each containing up to 16 blocks
			let num_chunks = max_len.div_ceil(1024);
			let blocks_per_chunk = 16;
			let mut chunk_outputs = Vec::new();

			// ---- 3b.2. Process each 1024-byte chunk
			for chunk_idx in 0..num_chunks {
				let chunk_start_byte = chunk_idx * 1024;
				let chunk_start_wire = builder.add_constant_64(chunk_start_byte as u64);
				let is_valid_chunk = builder.icmp_ult(chunk_start_wire, len);

				// Each chunk starts with IV as chaining value
				let mut cv = [builder.add_constant_64(0); 8];
				for i in 0..8 {
					cv[i] = builder.add_constant_64(IV[i] as u64);
				}

				// Track chunk output
				let mut chunk_output = [builder.add_constant_64(0); 8];

				// ---- 3b.2a. Process up to 16 blocks within this chunk
				for block_in_chunk in 0..blocks_per_chunk {
					// Global block index
					let global_block_idx = chunk_idx * blocks_per_chunk + block_in_chunk;
					let block_start_byte = global_block_idx * 64;
					let block_end_byte = block_start_byte + 64;

					// Check if this block is within valid data range
					let block_start_wire = builder.add_constant_64(block_start_byte as u64);
					let block_end_wire = builder.add_constant_64(block_end_byte as u64);

					// Is this block valid? (start < len)
					let is_valid_block = builder.icmp_ult(block_start_wire, len);

					// Is this the last block in the chunk?
					// This is true if EITHER:
					// 1. This is block 15 (last block of a full chunk), OR
					// 2. The data ends in this block (partial chunk)
					let is_block_15 = block_in_chunk == 15;
					let is_last_data_block = builder.bnot(builder.icmp_ult(block_end_wire, len));

					let is_last_in_chunk = builder.band(
						is_valid_block,
						builder
							.bor(builder.add_constant_64(is_block_15 as u64), is_last_data_block),
					);

					// Extract block data
					let mut block = [builder.add_constant_64(0); 16];
					let word_start = global_block_idx * 16;
					let word_end = ((global_block_idx + 1) * 16).min(message_words.len());

					if word_start < message_words.len() {
						block
							.iter_mut()
							.take(word_end - word_start)
							.zip(message_words[word_start..word_end].iter())
							.for_each(|(b, &m)| *b = m);
					}

					// Blake3 counter is the chunk index
					let counter = builder.add_constant_64(chunk_idx as u64);

					// Calculate block length
					let remaining_bytes = builder
						.isub_bin_bout(len, block_start_wire, builder.add_constant_64(0))
						.0;

					let is_partial = builder.icmp_ult(remaining_bytes, builder.add_constant_64(64));
					// select(a, b, cond) returns b if MSB(cond)=1, else a
					// If partial (MSB=1): use remaining_bytes
					// If full (MSB=0): use 64
					let block_len =
						builder.select(builder.add_constant_64(64), remaining_bytes, is_partial);

					// Calculate flags
					let mut flags = builder.add_constant_64(0);

					// CHUNK_START: First block of chunk (block 0 in chunk)
					if block_in_chunk == 0 {
						flags = builder.bor(flags, builder.add_constant_64(CHUNK_START as u64));
					}

					// CHUNK_END: Last valid block in chunk (conditional)
					let chunk_end_flag =
						builder.band(is_last_in_chunk, builder.add_constant_64(CHUNK_END as u64));
					flags = builder.bor(flags, chunk_end_flag);

					// ROOT: Only for single-chunk messages on the last block
					// For multi-chunk scenarios, ROOT is set on parent nodes, not chunk outputs
					// We need to conditionally set ROOT based on whether this is truly the only
					// chunk
					if num_chunks == 1 {
						// If max_chunks is 1, we know for sure this is a single-chunk message
						let root_flag =
							builder.band(is_last_in_chunk, builder.add_constant_64(ROOT as u64));
						flags = builder.bor(flags, root_flag);
					} else if num_chunks == 2 && chunk_idx == 0 {
						// For 2-chunk max, first chunk gets ROOT only if second chunk is invalid
						// Check if we're the only valid chunk
						let next_chunk_start = builder.add_constant_64(1024);
						let is_only_chunk = builder.bnot(builder.icmp_ult(next_chunk_start, len));
						let root_flag = builder.band(
							builder.band(is_last_in_chunk, is_only_chunk),
							builder.add_constant_64(ROOT as u64),
						);
						flags = builder.bor(flags, root_flag);
					}
					// For chunk_idx >= 1 in multi-chunk scenarios, never set ROOT on chunk output

					// Compress this block
					let block_output =
						compress::compress(builder, &cv, &block, counter, block_len, flags);

					// Update chaining value conditionally
					// Use builder.select for proper conditional assignment
					// select(a, b, cond) returns b if MSB(cond)=1, else a
					for i in 0..8 {
						// If valid block (MSB=1): use block_output[i]
						// If invalid block (MSB=0): keep cv[i]
						cv[i] = builder.select(cv[i], block_output[i], is_valid_block);
					}

					// Save output if this is the last block in the chunk
					// Use builder.select for proper conditional assignment
					for i in 0..8 {
						// If this is the last block in chunk (MSB=1): save cv[i]
						// Otherwise (MSB=0): keep chunk_output[i]
						chunk_output[i] = builder.select(chunk_output[i], cv[i], is_last_in_chunk);
					}
				}

				// Save this chunk's final output along with its validity flag
				// Note: Invalid chunks will have IV as their output (initial state)
				chunk_outputs.push((chunk_output, is_valid_chunk));
			}

			// Tree construction for multi-chunk inputs
			//
			// Blake3 uses a binary tree to combine chunk outputs.
			// Each parent node compresses the concatenation of two child hashes.
			//
			// NOTE: This implementation currently supports up to 2 chunks (2048 bytes).
			// For larger inputs, the tree structure becomes more complex and would
			// require additional implementation work.
			//
			let final_hash = if num_chunks > 1 {
				// Multi-chunk case - need to handle tree construction carefully
				if num_chunks == 2 {
					// Special case for exactly 2 max chunks
					let (chunk0, valid0) = chunk_outputs[0];
					let (chunk1, valid1) = chunk_outputs[1];

					// Determine if we have 1 or 2 valid chunks
					let is_two_chunks = builder.band(valid0, valid1);

					// Create parent node (used only if both chunks are valid)
					let parent = compress::combine_children(
						builder,
						&chunk0,
						&chunk1,                    // Use actual chunk1 (even if invalid)
						builder.add_constant_64(1), // is_root = true
					);

					// Select the appropriate result:
					// - If only chunk0 is valid: use chunk0 with ROOT flag
					// - If both chunks valid: use parent with ROOT flag
					let mut result = [builder.add_constant_64(0); 8];
					for i in 0..8 {
						result[i] = builder.select(chunk0[i], parent[i], is_two_chunks);
					}
					result
				} else {
					// Multi-chunk tree construction for >2 chunks not implemented
					// This would require complex dynamic tree logic incompatible with fixed
					// circuits
					panic!(
						"Blake3 circuit supports maximum 2048 bytes (2 chunks). For larger inputs, use Blake2s."
					);
				}
			} else {
				// Single chunk - output is just the chunk
				chunk_outputs[0].0 // Extract the chunk output (not the validity flag)
			};

			// Pack 32-bit words into 64-bit output wires
			let computed_output = [
				builder.bor(final_hash[0], builder.shl(final_hash[1], 32)),
				builder.bor(final_hash[2], builder.shl(final_hash[3], 32)),
				builder.bor(final_hash[4], builder.shl(final_hash[5], 32)),
				builder.bor(final_hash[6], builder.shl(final_hash[7], 32)),
			];

			// Create witness wires and add equality constraints
			let output = [
				builder.add_witness(),
				builder.add_witness(),
				builder.add_witness(),
				builder.add_witness(),
			];

			// Add equality constraints between computed and expected output
			for i in 0..4 {
				builder.assert_eq(
					format!("blake3_output_match_{}", i),
					computed_output[i],
					output[i],
				);
			}

			Blake3 {
				max_len,
				len,
				message,
				output,
			}
		}
	}

	/// Populates witness values for proof generation.
	///
	/// # Arguments
	/// * `witness` - Witness filler to populate
	/// * `message_bytes` - Input message to hash
	///
	/// # Panics
	/// If `message_bytes.len()` > `max_len`
	pub fn fill_witness(&self, witness: &mut WitnessFiller, message_bytes: &[u8]) {
		assert!(message_bytes.len() <= self.max_len, "Message exceeds maximum length");

		// Pack message bytes into 64-bit words (little-endian)
		for (i, chunk) in message_bytes.chunks(8).enumerate() {
			let mut word = 0u64;
			for (j, &byte) in chunk.iter().enumerate() {
				word |= (byte as u64) << (j * 8);
			}
			witness[self.message[i]] = Word(word);
		}

		// Zero-pad remaining wires
		for i in (message_bytes.len().div_ceil(8))..self.message.len() {
			witness[self.message[i]] = Word(0);
		}

		// Store actual message length
		witness[self.len] = Word(message_bytes.len() as u64);

		// Compute expected hash using reference implementation
		let hash = if message_bytes.len() <= 64 {
			reference::blake3_hash(message_bytes)
		} else {
			reference::blake3_hash_multi_block(message_bytes)
		};

		// Set output wires to computed hash value
		witness[self.output[0]] = Word(hash[0]);
		witness[self.output[1]] = Word(hash[1]);
		witness[self.output[2]] = Word(hash[2]);
		witness[self.output[3]] = Word(hash[3]);
	}
}

/// Creates a Blake3 circuit with private witness wires.
///
/// All inputs and outputs are private (witness wires), suitable for
/// zero-knowledge proving scenarios.
pub fn blake3_hash_witness(builder: &mut CircuitBuilder, max_len: usize) -> Blake3 {
	let len = builder.add_witness();
	let message = (0..max_len.div_ceil(8))
		.map(|_| builder.add_witness())
		.collect();

	Blake3::new(builder, max_len, len, message)
}

/// Creates a Blake3 circuit with public input/output wires.
///
/// Message and hash are public (inout wires), suitable for
/// transparent verification scenarios.
pub fn blake3_hash_public(builder: &mut CircuitBuilder, max_len: usize) -> Blake3 {
	let len = builder.add_inout();
	let message = (0..max_len.div_ceil(8))
		.map(|_| builder.add_inout())
		.collect();

	Blake3::new(builder, max_len, len, message)
}

#[cfg(test)]
mod tests {
	// Test modules organized by category
	mod differential_tests;
	mod edge_cases;
	mod flag_tests;
	mod multi_block_tests;
	mod official_vectors;
	mod performance_tests;
	mod property_tests;
	mod tree_validation;
	mod unit_tests;
}

// Main test suite
#[cfg(test)]
#[path = "tests.rs"]
mod main_tests;
