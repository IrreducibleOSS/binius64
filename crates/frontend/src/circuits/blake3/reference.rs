/// Blake3 reference implementation for witness generation
/// This module provides a pure Rust implementation of Blake3 for computing
/// witness values. It matches the official Blake3 algorithm exactly.
use super::{CHUNK_END, CHUNK_START, IV, MSG_SCHEDULE, ROOT};

/// Compute Blake3 hash for witness generation (single block <= 64 bytes)
pub fn blake3_hash(data: &[u8]) -> [u64; 4] {
	// Process single block (simplified for <=64 bytes)
	let mut block = [0u32; 16];

	// Pack message into 32-bit words (little-endian)
	for (i, chunk) in data.chunks(4).enumerate() {
		let mut word = 0u32;
		for (j, &byte) in chunk.iter().enumerate() {
			word |= (byte as u32) << (j * 8);
		}
		block[i] = word;
	}

	// Apply compression with flags for single chunk
	let flags = CHUNK_START | CHUNK_END | ROOT;
	let state = compress_reference(&IV, &block, 0, data.len() as u32, flags);

	// Pack into 64-bit words for output (little-endian)
	[
		(state[0] as u64) | ((state[1] as u64) << 32),
		(state[2] as u64) | ((state[3] as u64) << 32),
		(state[4] as u64) | ((state[5] as u64) << 32),
		(state[6] as u64) | ((state[7] as u64) << 32),
	]
}

/// Blake3 compression function
fn compress_reference(
	cv: &[u32; 8],
	block: &[u32; 16],
	counter: u64,
	block_len: u32,
	flags: u32,
) -> [u32; 8] {
	let mut state = [0u32; 16];

	// Initialize state matrix
	state[0..8].copy_from_slice(cv);
	state[8..12].copy_from_slice(&IV[0..4]);
	state[12] = counter as u32;
	state[13] = (counter >> 32) as u32;
	state[14] = block_len;
	state[15] = flags;

	// 7 rounds of mixing (reduced from standard 12)
	for round in 0..7 {
		apply_round(&mut state, block, round);
	}

	// Output is XOR of top and bottom halves
	let mut output = [0u32; 8];
	for i in 0..8 {
		output[i] = state[i] ^ state[i + 8];
	}
	output
}

/// Apply one round of Blake3 mixing
fn apply_round(state: &mut [u32; 16], msg: &[u32; 16], round: usize) {
	let schedule = MSG_SCHEDULE[round];

	// Column G-functions (operate on columns of 4x4 state matrix)
	g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
	g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
	g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
	g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

	// Diagonal G-functions
	g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
	g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
	g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
	g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

/// Blake3 G-function (mixing function)
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
	state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
	state[d] = (state[d] ^ state[a]).rotate_right(16);
	state[c] = state[c].wrapping_add(state[d]);
	state[b] = (state[b] ^ state[c]).rotate_right(12);
	state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
	state[d] = (state[d] ^ state[a]).rotate_right(8);
	state[c] = state[c].wrapping_add(state[d]);
	state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// Compute Blake3 hash for multi-block inputs
pub fn blake3_hash_multi_block(data: &[u8]) -> [u64; 4] {
	if data.len() <= 64 {
		return blake3_hash(data);
	}

	// Blake3 uses 1024-byte chunks, each containing up to 16 blocks of 64 bytes
	let num_chunks = data.len().div_ceil(1024);
	let mut chunk_outputs = Vec::new();

	// Process each 1024-byte chunk
	for chunk_idx in 0..num_chunks {
		let chunk_start = chunk_idx * 1024;
		let chunk_end = ((chunk_idx + 1) * 1024).min(data.len());
		let chunk_data = &data[chunk_start..chunk_end];

		// Each chunk starts with IV as chaining value
		let mut cv = IV;

		// Process up to 16 blocks within this chunk
		for (block_in_chunk, block_data) in chunk_data.chunks(64).enumerate() {
			let mut block = [0u32; 16];

			// Pack block into 32-bit words
			for (i, word_bytes) in block_data.chunks(4).enumerate() {
				let mut word = 0u32;
				for (j, &byte) in word_bytes.iter().enumerate() {
					word |= (byte as u32) << (j * 8);
				}
				block[i] = word;
			}

			// Set flags based on position within chunk
			let mut flags = 0u32;
			if block_in_chunk == 0 {
				flags |= CHUNK_START;
			}

			// Check if this is the last block in the chunk
			let is_last_in_chunk = (block_in_chunk + 1) * 64 >= chunk_data.len();
			if is_last_in_chunk {
				flags |= CHUNK_END;
				// ROOT flag only for single-chunk messages
				if num_chunks == 1 {
					flags |= ROOT;
				}
			}

			// Compress block with chunk_counter (not block index!)
			// The counter in Blake3 is the chunk number, not the block index
			cv = compress_reference(
				&cv,
				&block,
				chunk_idx as u64, // This should be chunk_idx, not global_block_idx!
				block_data.len() as u32,
				flags,
			);
		}

		// Save chunk's final chaining value
		chunk_outputs.push(cv);
	}

	// Build tree from chunk outputs for multi-chunk inputs
	let final_output = if num_chunks > 1 {
		build_tree(&chunk_outputs)
	} else {
		chunk_outputs[0]
	};

	// Convert to 64-bit output format
	[
		(final_output[0] as u64) | ((final_output[1] as u64) << 32),
		(final_output[2] as u64) | ((final_output[3] as u64) << 32),
		(final_output[4] as u64) | ((final_output[5] as u64) << 32),
		(final_output[6] as u64) | ((final_output[7] as u64) << 32),
	]
}

/// Build Blake3 binary tree from chunk outputs
fn build_tree(chunk_outputs: &[[u32; 8]]) -> [u32; 8] {
	if chunk_outputs.len() == 1 {
		return chunk_outputs[0];
	}

	let mut layer = chunk_outputs.to_vec();

	while layer.len() > 1 {
		let mut next_layer = Vec::new();

		for pair in layer.chunks(2) {
			if pair.len() == 2 {
				// Combine two children into parent
				let parent = combine_children(&pair[0], &pair[1], layer.len() == 2);
				next_layer.push(parent);
			} else {
				// Odd node - promote to next level
				next_layer.push(pair[0]);
			}
		}

		layer = next_layer;
	}

	layer[0]
}

/// Combine two child hashes into a parent node
fn combine_children(left: &[u32; 8], right: &[u32; 8], is_root: bool) -> [u32; 8] {
	let mut block = [0u32; 16];

	// Parent block contains concatenation of children
	block[..8].copy_from_slice(left);
	block[8..16].copy_from_slice(right);

	// Parent nodes use IV, counter=0, and PARENT flag
	let mut flags = super::PARENT;
	if is_root {
		flags |= ROOT;
	}

	compress_reference(&IV, &block, 0, 64, flags)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn bytes_to_hex(bytes: &[u8]) -> String {
		bytes
			.iter()
			.map(|b| format!("{:02x}", b))
			.collect::<String>()
	}

	fn hash_to_bytes(hash: &[u64; 4]) -> Vec<u8> {
		let mut bytes = Vec::new();
		for &word in hash {
			bytes.extend_from_slice(&word.to_le_bytes());
		}
		bytes
	}

	#[test]
	fn test_blake3_empty() {
		let hash = blake3_hash(b"");
		let hash_hex = bytes_to_hex(&hash_to_bytes(&hash));
		// Blake3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
		assert_eq!(&hash_hex[0..8], "af1349b9");
	}

	#[test]
	fn test_blake3_single_byte() {
		let hash = blake3_hash(b"a");
		let hash_hex = bytes_to_hex(&hash_to_bytes(&hash));
		// Blake3("a") = 17762fddd969a453925d65717ac3eea21320b66b54342fde15128d6caf21215f
		assert_eq!(&hash_hex[0..8], "17762fdd");
	}

	#[test]
	fn test_blake3_abc() {
		let hash = blake3_hash(b"abc");
		let hash_hex = bytes_to_hex(&hash_to_bytes(&hash));
		// Blake3("abc") = 6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85
		assert_eq!(&hash_hex[0..8], "6437b3ac");
	}

	#[test]
	fn test_blake3_fox() {
		let hash = blake3_hash(b"The quick brown fox jumps over the lazy dog");
		let hash_hex = bytes_to_hex(&hash_to_bytes(&hash));
		// Blake3("The quick brown fox...") =
		// 2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a
		assert_eq!(&hash_hex[0..8], "2f151418");
	}

	#[test]
	fn test_reference_vs_official() {
		// Test cases of various lengths
		let test_cases = vec![
			vec![],                                                  // Empty
			b"a".to_vec(),                                           // 1 byte
			b"abc".to_vec(),                                         // 3 bytes
			b"The quick brown fox jumps over the lazy dog".to_vec(), // 44 bytes
			vec![b'A'; 64],                                          // Exactly 64 bytes
			vec![b'B'; 65],                                          // 65 bytes (2 blocks)
			vec![b'C'; 128],                                         // 128 bytes
			vec![b'D'; 1024],                                        // 1024 bytes (1 chunk)
			vec![b'E'; 1025],                                        // 1025 bytes (2 chunks)
		];

		let mut failures = Vec::new();

		for test_data in test_cases {
			// Get hash from official blake3 crate
			let official_hash = blake3::hash(&test_data);
			let official_bytes = official_hash.as_bytes();

			// Get hash from our reference implementation
			let our_hash = if test_data.len() <= 64 {
				blake3_hash(&test_data)
			} else {
				blake3_hash_multi_block(&test_data)
			};

			// Convert our hash to bytes for comparison
			let our_bytes = hash_to_bytes(&our_hash);

			// Compare
			if official_bytes != &our_bytes[..] {
				failures.push((
					test_data.len(),
					bytes_to_hex(official_bytes),
					bytes_to_hex(&our_bytes),
				));
			}
		}

		assert!(
			failures.is_empty(),
			"\n❌ Reference implementation does not match official blake3!\nFailures: {:?}",
			failures
		);
	}
}
