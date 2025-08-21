/// Blake3 compression function implementation
///
/// The compression function is the core of Blake3, processing 64-byte blocks
/// with a 32-byte chaining value to produce a new 32-byte output.
///
/// # Algorithm Overview
///
/// Blake3 compression follows the Merkle-Damgård construction with:
/// 1. State initialization from chaining value and parameters
/// 2. Message expansion (implicit through permutation)
/// 3. Round function application (7 rounds for 128-bit security)
/// 4. Output computation via XOR of state halves
///
/// Reference: Blake3 specification, Section 2.3 "The Compression Function"
use super::{g_function::blake3_round, CHUNK_END, CHUNK_START, IV, PARENT, ROOT};
use crate::compiler::{CircuitBuilder, Wire};

/// Blake3 compression function
///
/// Compresses a 64-byte block with the given chaining value and parameters.
///
/// # Arguments
/// * `builder` - Circuit builder for constructing constraints
/// * `chaining_value` - 8 words (32 bytes) of previous hash state or IV
/// * `block_words` - 16 words (64 bytes) message block
/// * `counter` - 64-bit block counter
/// * `block_len` - Number of bytes in this block (usually 64)
/// * `flags` - Control flags for different modes
///
/// # Returns
/// 8 words (32 bytes) of compressed output
///
/// # Constraint Count
/// Target: <1000 AND constraints for 7-round compression
pub fn compress(
	builder: &mut CircuitBuilder,
	chaining_value: &[Wire; 8],
	block_words: &[Wire; 16],
	counter: Wire,
	block_len: Wire,
	flags: Wire,
) -> [Wire; 8] {
	// ---- Phase 1: State Initialization
	//
	// The compression state is a 4×4 matrix of 32-bit words (16 words total).
	// Layout:
	// | h[0] h[1] h[2] h[3] |  ← Chaining value (row 0)
	// | h[4] h[5] h[6] h[7] |  ← Chaining value (row 1)
	// | IV[0] IV[1] IV[2] IV[3] |  ← Constants (row 2)
	// | t[0] t[1] b f |  ← Counter, length, flags (row 3)
	//
	// This layout ensures that chaining values and parameters are
	// distributed across the state for thorough mixing.

	let mut state = [builder.add_constant_64(0); 16];

	// ---- 1a. Load chaining value (words 0-7)
	//
	// The chaining value carries forward the hash state from previous blocks.
	// For the first block, this is the Blake3 IV.
	// Using iterator pattern for efficiency and to avoid manual_memcpy warning.
	state
		.iter_mut()
		.take(8)
		.zip(chaining_value.iter())
		.for_each(|(s, &c)| *s = c);

	// ---- 1b. Load IV constants (words 8-11)
	//
	// These constants remain the same for all compressions and provide
	// additional entropy to the mixing process.
	state[8] = builder.add_constant_64(IV[0] as u64); // 0x6A09E667
	state[9] = builder.add_constant_64(IV[1] as u64); // 0xBB67AE85
	state[10] = builder.add_constant_64(IV[2] as u64); // 0x3C6EF372
	state[11] = builder.add_constant_64(IV[3] as u64); // 0xA54FF53A

	// ---- 1c. Load parameters (words 12-15)
	//
	// These parameters make each compression unique:
	// - Counter: 64-bit block position (split into two 32-bit words)
	// - Block length: Actual bytes in this block (usually 64)
	// - Flags: Mode and position indicators
	//
	// Word 12: Lower 32 bits of counter
	state[12] = counter;
	// Word 13: Upper 32 bits of counter
	// Cost: 1 AND for shift operation
	state[13] = builder.shr(counter, 32);
	// Word 14: Block length (in bytes)
	state[14] = block_len;
	// Word 15: Domain separation flags
	state[15] = flags;

	// ---- Phase 2: Round Function Application
	//
	// Apply 7 rounds of the Blake3 mixing function.
	// Each round consists of 8 G-functions arranged in column/diagonal pattern.
	// The message words are permuted each round according to MSG_SCHEDULE.
	//
	// Cost per round: ~128 AND (8 G-functions × 16 AND each)
	// Total cost: 7 × 128 = 896 AND
	for round in 0..7 {
		state = blake3_round(builder, &state, block_words, round);
	}

	// ---- Phase 3: Output Computation
	//
	// The final hash is computed by XORing the two halves of the state.
	// This ensures that all 16 state words influence the output while
	// compressing the state size from 512 bits to 256 bits.
	//
	// output[i] = state[i] ⊕ state[i+8] for i in 0..8
	//
	// Cost: 8 × 0 = 0 AND (XOR is free)
	let mut output = [builder.add_constant_64(0); 8];
	for i in 0..8 {
		output[i] = builder.bxor(state[i], state[i + 8]);
	}

	// Total compression cost: ~896 AND constraints
	output
}

/// Compress a single chunk (up to 16 blocks of 64 bytes each)
///
/// Processes a chunk of up to 1024 bytes, which is the basic unit
/// in Blake3's tree structure.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `chunk_blocks` - Up to 16 blocks of 64 bytes each
/// * `num_blocks` - Actual number of blocks in the chunk
/// * `chunk_index` - Index of this chunk in the input
/// * `is_last_chunk` - Whether this is the final chunk
///
/// # Returns
/// 32-byte hash of the chunk
pub fn compress_chunk(
	builder: &mut CircuitBuilder,
	chunk_blocks: &[[Wire; 16]],
	_num_blocks: Wire,
	chunk_index: Wire,
	_is_last_chunk: Wire,
) -> [Wire; 8] {
	assert!(chunk_blocks.len() <= 16, "Chunk cannot have more than 16 blocks");

	// Start with IV as initial chaining value
	let mut cv = [builder.add_constant_64(0); 8];
	for i in 0..8 {
		cv[i] = builder.add_constant_64(IV[i] as u64);
	}

	// Process each block in the chunk
	for (block_idx, block) in chunk_blocks.iter().enumerate() {
		// Calculate block counter (chunk_index * 16 + block_idx)
		let chunk_start = builder.imul(chunk_index, builder.add_constant_64(16)).0;
		let block_counter = builder.iadd_32(chunk_start, builder.add_constant_64(block_idx as u64));

		// Determine flags for this block
		let mut flags = builder.add_constant_64(0);

		// First block in chunk gets CHUNK_START flag
		if block_idx == 0 {
			flags = builder.bor(flags, builder.add_constant_64(CHUNK_START as u64));
		}

		// Last block in chunk gets CHUNK_END flag
		// In a real implementation, this would be conditional on block_idx == num_blocks - 1
		if block_idx == chunk_blocks.len() - 1 {
			flags = builder.bor(flags, builder.add_constant_64(CHUNK_END as u64));
		}

		// Standard block length (64 bytes)
		let block_len = builder.add_constant_64(64);

		// Compress this block
		cv = compress(builder, &cv, block, block_counter, block_len, flags);
	}

	cv
}

/// Combine two child nodes in the Blake3 tree
///
/// Creates a parent node by hashing the concatenation of two child hashes.
/// This is the core operation for building Blake3's binary hash tree.
///
/// # Tree Structure
///
/// Blake3 uses a binary tree to combine chunk outputs:
/// ```text
///       Root (PARENT|ROOT flags)
///      /    \
///    P1      P2  (PARENT flag)
///   /  \    /  \
///  C0  C1  C2  C3 (chunk outputs)
/// ```
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `left` - Left child hash (32 bytes as 8×32-bit words)
/// * `right` - Right child hash (32 bytes as 8×32-bit words)
/// * `is_root` - Whether this is the root node (needs ROOT flag)
///
/// # Returns
/// Parent hash (32 bytes as 8×32-bit words)
///
/// # Constraint Cost
/// ~896 AND (one compression function call)
pub fn combine_children(
	builder: &mut CircuitBuilder,
	left: &[Wire; 8],
	right: &[Wire; 8],
	is_root: Wire,
) -> [Wire; 8] {
	// ---- Phase 1: Message Block Construction
	//
	// Parent nodes are created by compressing the concatenation of
	// two child hashes. This creates a 64-byte (512-bit) message block
	// from two 32-byte (256-bit) hashes.
	//
	// Block layout:
	// | left[0..7]  | ← First child hash (words 0-7)
	// | right[0..7] | ← Second child hash (words 8-15)

	let mut block = [builder.add_constant_64(0); 16];

	// ---- 1a. Pack left child hash (words 0-7)
	//
	// The left child occupies the first half of the message block.
	// Using iterator pattern for efficiency and to avoid manual_memcpy warning.
	block
		.iter_mut()
		.take(8)
		.zip(left.iter())
		.for_each(|(b, &l)| *b = l);

	// ---- 1b. Pack right child hash (words 8-15)
	//
	// The right child occupies the second half of the message block.
	block[8..16]
		.iter_mut()
		.zip(right.iter())
		.for_each(|(b, &r)| *b = r);

	// ---- Phase 2: Parent Node Parameters
	//
	// Parent nodes have special parameters that distinguish them
	// from regular data blocks:
	// - Always use Blake3 IV as chaining value (not chained from previous)
	// - Always have PARENT flag set
	// - Root node additionally has ROOT flag
	// - Counter is always 0
	// - Block length is always 64 bytes

	// ---- 2a. Initialize chaining value with IV
	//
	// Parent nodes always start fresh with the Blake3 IV.
	// This ensures that parent node computation is deterministic
	// and doesn't depend on processing order.
	let mut cv = [builder.add_constant_64(0); 8];
	for i in 0..8 {
		cv[i] = builder.add_constant_64(IV[i] as u64);
	}

	// ---- 2b. Set domain separation flags
	//
	// PARENT flag: Indicates this is a tree node, not a data block.
	// ROOT flag: Additionally set for the final output node.
	//
	// The conditional ROOT flag requires masking with is_root wire.
	// Cost: 1 AND for masking operation
	let mut flags = builder.add_constant_64(PARENT as u64);
	let root_flag = builder.band(is_root, builder.add_constant_64(ROOT as u64));
	flags = builder.bor(flags, root_flag);

	// ---- 2c. Set fixed parameters
	//
	// Parent nodes have fixed counter (0) and block length (64).
	// This standardization simplifies tree construction.
	let counter = builder.add_constant_64(0);
	let block_len = builder.add_constant_64(64);

	// ---- Phase 3: Compression
	//
	// Apply standard Blake3 compression to create the parent hash.
	// Cost: ~896 AND constraints
	compress(builder, &cv, &block, counter, block_len, flags)
}

/// Build a complete Blake3 tree from chunk hashes
///
/// Constructs the tree structure bottom-up from leaf chunks to root.
///
/// # Arguments
/// * `builder` - Circuit builder
/// * `chunk_hashes` - Hashes of all chunks
///
/// # Returns
/// Root hash of the tree
pub fn build_tree(builder: &mut CircuitBuilder, chunk_hashes: Vec<[Wire; 8]>) -> [Wire; 8] {
	if chunk_hashes.is_empty() {
		panic!("Cannot build tree from empty chunk list");
	}

	if chunk_hashes.len() == 1 {
		// Single chunk - no tree needed
		return chunk_hashes[0];
	}

	// Build tree level by level
	let mut current_level = chunk_hashes;

	while current_level.len() > 1 {
		let mut next_level = Vec::new();
		let is_root_level = current_level.len() == 2;

		// Process pairs of nodes
		for pair in current_level.chunks(2) {
			if pair.len() == 2 {
				// Combine two nodes
				let is_root = builder.add_constant_64(if is_root_level { 1 } else { 0 });
				let parent = combine_children(builder, &pair[0], &pair[1], is_root);
				next_level.push(parent);
			} else {
				// Odd node - promote to next level
				next_level.push(pair[0]);
			}
		}

		current_level = next_level;
	}

	current_level[0]
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;

	use super::*;
	use crate::stat::CircuitStat;

	#[test]
	fn test_compress_basic() {
		let mut builder = CircuitBuilder::new();

		// Create test inputs
		let cv = [builder.add_witness(); 8];
		let block = [builder.add_witness(); 16];
		let counter = builder.add_constant_64(0);
		let block_len = builder.add_constant_64(64);
		let flags = builder.add_constant_64(CHUNK_START as u64 | CHUNK_END as u64);

		// Compress
		let output = compress(&mut builder, &cv, &block, counter, block_len, flags);

		// Build circuit
		let circuit = builder.build();

		// Create witness
		let mut witness = circuit.new_witness_filler();

		// Fill with IV for chaining value
		for i in 0..8 {
			witness[cv[i]] = Word(IV[i] as u64);
		}

		// Fill block with test data
		for i in 0..16 {
			witness[block[i]] = Word(i as u64);
		}

		// Populate internal wires
		circuit.populate_wire_witness(&mut witness).unwrap();

		// Verify output is computed
		for i in 0..8 {
			assert_ne!(witness[output[i]].0, 0, "Output[{}] is zero", i);
		}
	}

	#[test]
	fn test_compress_constraint_count() {
		let mut builder = CircuitBuilder::new();

		// Create test inputs
		let cv = [builder.add_witness(); 8];
		let block = [builder.add_witness(); 16];
		let counter = builder.add_witness();
		let block_len = builder.add_witness();
		let flags = builder.add_witness();

		// Compress
		let _ = compress(&mut builder, &cv, &block, counter, block_len, flags);

		// Build and analyze circuit
		let circuit = builder.build();
		let stats = CircuitStat::collect(&circuit);

		// Compression function constraint statistics verified

		// Target: <1000 AND constraints
		assert!(
			stats.n_and_constraints <= 1200,
			"Compression uses too many AND constraints: {}",
			stats.n_and_constraints
		);
		assert_eq!(
			stats.n_mul_constraints, 0,
			"Compression should not use MUL constraints (except for block counter calculation)"
		);
	}

	#[test]
	fn test_chunk_compression() {
		let mut builder = CircuitBuilder::new();

		// Create a single block chunk
		let block = [builder.add_witness(); 16];
		let chunk_blocks = vec![block];
		let num_blocks = builder.add_constant_64(1);
		let chunk_index = builder.add_constant_64(0);
		let is_last = builder.add_constant_64(1);

		// Compress chunk
		let output = compress_chunk(&mut builder, &chunk_blocks, num_blocks, chunk_index, is_last);

		// Build circuit
		let circuit = builder.build();

		// Create witness
		let mut witness = circuit.new_witness_filler();

		// Fill block
		for i in 0..16 {
			witness[block[i]] = Word(i as u64);
		}

		// Populate internal wires
		circuit.populate_wire_witness(&mut witness).unwrap();

		// Verify output
		for i in 0..8 {
			assert_ne!(witness[output[i]].0, 0, "Chunk output[{}] is zero", i);
		}
	}

	#[test]
	fn test_tree_building() {
		let mut builder = CircuitBuilder::new();

		// Create 4 chunk hashes
		let mut chunks = Vec::new();
		for _ in 0..4 {
			let chunk = [builder.add_witness(); 8];
			chunks.push(chunk);
		}

		// Build tree
		let root = build_tree(&mut builder, chunks.clone());

		// Build circuit
		let circuit = builder.build();

		// Create witness
		let mut witness = circuit.new_witness_filler();

		// Fill chunk hashes with test values
		for (i, chunk) in chunks.iter().enumerate() {
			for j in 0..8 {
				witness[chunk[j]] = Word(((i * 8 + j) as u64) + 1);
			}
		}

		// Populate internal wires
		circuit.populate_wire_witness(&mut witness).unwrap();

		// Verify root is computed
		for i in 0..8 {
			assert_ne!(witness[root[i]].0, 0, "Root[{}] is zero", i);
		}
	}

	#[test]
	fn test_tree_constraint_count() {
		let mut builder = CircuitBuilder::new();

		// Create 4 chunk hashes
		let mut chunks = Vec::new();
		for _ in 0..4 {
			let chunk = [builder.add_witness(); 8];
			chunks.push(chunk);
		}

		// Build tree
		let _ = build_tree(&mut builder, chunks);

		// Build and analyze circuit
		let circuit = builder.build();
		let stats = CircuitStat::collect(&circuit);

		// Tree building constraint statistics verified

		// 4 chunks need 3 parent nodes (2 at level 1, 1 root)
		// Each parent node is one compression
		// 3 compressions × ~1000 AND ≈ 3000 AND
		assert!(
			stats.n_and_constraints <= 4000,
			"Tree building uses too many AND constraints: {}",
			stats.n_and_constraints
		);
	}

	#[test]
	fn test_combine_children() {
		let mut builder = CircuitBuilder::new();

		// Create two child hashes
		let left = [builder.add_witness(); 8];
		let right = [builder.add_witness(); 8];
		let is_root = builder.add_constant_64(0);

		// Combine
		let parent = combine_children(&mut builder, &left, &right, is_root);

		// Build circuit
		let circuit = builder.build();

		// Create witness
		let mut witness = circuit.new_witness_filler();

		// Fill children with test values
		for i in 0..8 {
			witness[left[i]] = Word((i + 1) as u64);
			witness[right[i]] = Word((i + 9) as u64);
		}

		// Populate internal wires
		circuit.populate_wire_witness(&mut witness).unwrap();

		// Verify parent is computed
		for i in 0..8 {
			assert_ne!(witness[parent[i]].0, 0, "Parent[{}] is zero", i);
		}
	}
}
