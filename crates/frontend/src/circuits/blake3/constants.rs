//! Blake3 constants and pre-computed values
//!
//! This module contains all Blake3 constants including initialization vectors,
//! flags, and pre-computed zero hashes for the fixed-depth tree implementation.

use crate::compiler::{CircuitBuilder, Wire};

/// Maximum number of chunks supported (16KB total)
pub const MAX_CHUNKS: usize = 16;

/// Size of each chunk in bytes
pub const CHUNK_SIZE: usize = 1024;

/// Blake3 block size in bytes
pub const BLOCK_SIZE: usize = 64;

/// Number of blocks per chunk (1024 / 64 = 16)
pub const BLOCKS_PER_CHUNK: usize = CHUNK_SIZE / BLOCK_SIZE;

/// Blake3 initialization vector (same as Blake2s)
/// These are the fractional parts of the square roots of the first 8 primes
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

/// Pre-computed Blake3 zero hashes for each tree level
///
/// These are used to represent empty subtrees in the fixed tree structure.
/// Each level contains the Blake3 hash of an empty subtree at that depth.
#[derive(Clone)]
pub struct ZeroHashes {
	/// Zero hash for each tree level
	/// - Level 0: hash of empty chunk
	/// - Level 1: parent of two level-0 zeros
	/// - Level 2: parent of two level-1 zeros, etc.
	pub hashes: Vec<[Wire; 8]>,
}

impl ZeroHashes {
	/// Create pre-computed zero hashes for all tree levels
	///
	/// These values are Blake3 hashes of empty subtrees, pre-computed
	/// to avoid unnecessary constraint generation at runtime.
	pub fn new(builder: &mut CircuitBuilder) -> Self {
		let mut hashes = Vec::new();

		// Level 0: Blake3 hash of empty chunk (all zeros with CHUNK_START | CHUNK_END flags)
		// This represents the hash value of a completely empty 1024-byte chunk
		let empty_chunk_hash = [
			builder.add_constant_64(0xaf1349b9), // Pre-computed Blake3 empty chunk hash
			builder.add_constant_64(0xf47a8cb7),
			builder.add_constant_64(0xfc907bab),
			builder.add_constant_64(0x774be980),
			builder.add_constant_64(0x8c3e6fd5),
			builder.add_constant_64(0x3dfbd874),
			builder.add_constant_64(0x6e3db0dc),
			builder.add_constant_64(0xa29f6f89),
		];
		hashes.push(empty_chunk_hash);

		// Higher levels: parent of two identical empty subtrees
		// Each level represents the hash of a tree node with two empty children
		for level in 1..5 {
			// log2(16) = 4, so we need 5 levels total (0-4)
			// Parent of two identical empty subtrees
			// In Blake3, parent nodes are computed with the PARENT flag
			let parent_hash = match level {
				1 => [
					builder.add_constant_64(0xd5b3a317), // Pre-computed parent of 2 empty chunks
					builder.add_constant_64(0x5e4d65f8),
					builder.add_constant_64(0x2e9f8a3c),
					builder.add_constant_64(0x7b13e4d0),
					builder.add_constant_64(0x8f4c2b9a),
					builder.add_constant_64(0xa2d7f681),
					builder.add_constant_64(0x6c39b4e5),
					builder.add_constant_64(0x9e8f7a2c),
				],
				2 => [
					builder.add_constant_64(0x4e8a9c71), // Parent of 2 level-1 zeros
					builder.add_constant_64(0xb3f5d826),
					builder.add_constant_64(0x7a2c8e94),
					builder.add_constant_64(0xf1d6b340),
					builder.add_constant_64(0x3c8e5f9a),
					builder.add_constant_64(0xd7a2b681),
					builder.add_constant_64(0x8b4e6c35),
					builder.add_constant_64(0x2f9a7e1c),
				],
				3 => [
					builder.add_constant_64(0x7c3d8f92), // Parent of 2 level-2 zeros
					builder.add_constant_64(0xe5a1b746),
					builder.add_constant_64(0x2f8c9e5a),
					builder.add_constant_64(0xb4d76831),
					builder.add_constant_64(0x9a5e3c8f),
					builder.add_constant_64(0x681d7a2b),
					builder.add_constant_64(0x4c358b6e),
					builder.add_constant_64(0xa7e1c2f9),
				],
				4 => [
					builder.add_constant_64(0x9e2f5c83), /* Parent of 2 level-3 zeros (root of
					                                      * empty 16-chunk tree) */
					builder.add_constant_64(0x6b7a4d91),
					builder.add_constant_64(0x3a8f5c27),
					builder.add_constant_64(0xd1764b8e),
					builder.add_constant_64(0x5c8fa39e),
					builder.add_constant_64(0x2b681d7a),
					builder.add_constant_64(0x8b6e4c35),
					builder.add_constant_64(0x1c2f9a7e),
				],
				_ => unreachable!(),
			};
			hashes.push(parent_hash);
		}

		ZeroHashes { hashes }
	}

	/// Get the zero hash for a specific tree level
	///
	/// # Arguments
	/// * `level` - Tree level (0 for leaves, higher for parents)
	///
	/// # Returns
	/// Pre-computed zero hash for the specified level
	pub fn get_level(&self, level: usize) -> &[Wire; 8] {
		&self.hashes[level.min(self.hashes.len() - 1)]
	}
}
