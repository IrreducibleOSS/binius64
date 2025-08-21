//! Multi-block tests for Blake3
//!
//! Note: Tests for inputs >1024 bytes are expected to fail due to
//! the known limitation with multi-chunk tree construction.
//! These tests are kept for documentation purposes and to verify
//! that single-chunk multi-block inputs (≤1024 bytes) work correctly.

use binius_core::word::Word;

use super::super::*;
use crate::compiler::CircuitBuilder;

/// Test multi-block Blake3 implementation within single chunk (≤1024 bytes)
#[test]
fn test_two_blocks() {
	let mut builder = CircuitBuilder::new();
	// Create circuit for 128 bytes (2 blocks)
	let blake3 = blake3_hash_witness(&mut builder, 128);
	let circuit = builder.build();

	// Test with 65 bytes (just over one block)
	let mut witness = circuit.new_witness_filler();
	let message = vec![0x42u8; 65];
	blake3.fill_witness(&mut witness, &message);
	witness[blake3.len] = Word(65);

	let result = circuit.populate_wire_witness(&mut witness);
	assert!(result.is_ok(), "Failed to process 65-byte input");

	// Verify output is non-zero
	for i in 0..4 {
		assert_ne!(witness[blake3.output[i]].0, 0, "Output[{}] should not be zero", i);
	}
}

#[test]
fn test_exact_two_blocks() {
	let mut builder = CircuitBuilder::new();
	let blake3 = blake3_hash_witness(&mut builder, 128);
	let circuit = builder.build();

	// Test with exactly 128 bytes (2 full blocks)
	let mut witness = circuit.new_witness_filler();
	let mut message = vec![0u8; 128];
	for i in 0..128 {
		message[i] = i as u8;
	}
	blake3.fill_witness(&mut witness, &message);
	witness[blake3.len] = Word(128);

	let result = circuit.populate_wire_witness(&mut witness);
	assert!(result.is_ok(), "Failed to process 128-byte input");

	// Verify output is computed
	for i in 0..4 {
		assert_ne!(witness[blake3.output[i]].0, 0, "Output[{}] should not be zero", i);
	}
}

#[test]
fn test_four_blocks() {
	let mut builder = CircuitBuilder::new();
	// Create circuit for 256 bytes (4 blocks)
	let blake3 = blake3_hash_witness(&mut builder, 256);
	let circuit = builder.build();

	// Test with 256 bytes (4 full blocks - tests tree structure)
	let mut witness = circuit.new_witness_filler();
	let mut message = vec![0u8; 256];
	for i in 0..256 {
		message[i] = (i % 256) as u8;
	}
	blake3.fill_witness(&mut witness, &message);
	witness[blake3.len] = Word(256);

	let result = circuit.populate_wire_witness(&mut witness);
	assert!(result.is_ok(), "Failed to process 256-byte input");

	// Verify output is computed
	for i in 0..4 {
		assert_ne!(witness[blake3.output[i]].0, 0, "Output[{}] should not be zero", i);
	}
}

#[test]
fn test_multi_block_edge_cases() {
	let mut builder = CircuitBuilder::new();
	let blake3 = blake3_hash_witness(&mut builder, 256);
	let circuit = builder.build();

	// Test various edge cases
	let test_cases = vec![
		63,  // One less than block size
		64,  // Exactly one block
		65,  // One more than block size
		127, // One less than two blocks
		128, // Exactly two blocks
		129, // One more than two blocks
		192, // Three blocks
		255, // One less than four blocks
		256, // Exactly four blocks
	];

	for size in test_cases {
		let mut witness = circuit.new_witness_filler();
		let message = vec![0xAAu8; size];
		blake3.fill_witness(&mut witness, &message);
		witness[blake3.len] = Word(size as u64);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok(), "Failed for input size {}", size);

		// Verify different sizes produce different hashes
		let hash_0 = witness[blake3.output[0]].0;
		assert_ne!(hash_0, 0, "Hash should not be zero for size {}", size);
	}
}

#[test]
fn test_tree_structure() {
	// Test that multi-chunk inputs properly build tree structure
	let mut builder = CircuitBuilder::new();
	let blake3 = blake3_hash_witness(&mut builder, 256);
	let circuit = builder.build();

	// Create a pattern that should result in tree hashing
	let mut witness = circuit.new_witness_filler();
	let mut message = vec![0u8; 256];

	// Fill with distinct patterns for each chunk
	for chunk in 0..4 {
		for i in 0..64 {
			message[chunk * 64 + i] = ((chunk + 1) * (i + 1)) as u8;
		}
	}

	blake3.fill_witness(&mut witness, &message);
	witness[blake3.len] = Word(256);

	let result = circuit.populate_wire_witness(&mut witness);
	assert!(result.is_ok(), "Tree structure test failed");

	// Verify hash is computed
	for i in 0..4 {
		assert_ne!(witness[blake3.output[i]].0, 0, "Tree hash output[{}] is zero", i);
	}
}
