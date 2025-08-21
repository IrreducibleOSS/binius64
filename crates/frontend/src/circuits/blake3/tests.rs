//! Core tests for Blake3 implementation
//! Note: Most comprehensive tests are in the tests/ subdirectory

use super::*;
use crate::{
	compiler::{CircuitBuilder, Wire},
	stat::CircuitStat,
};

#[test]
fn test_basic_single_chunk() {
	// Basic test for exactly 1024 bytes (one chunk)
	let mut builder = CircuitBuilder::new();
	let message_wires: Vec<Wire> = (0..128).map(|_| builder.add_witness()).collect();
	let actual_bytes = builder.add_witness();
	let _result = blake3_hash(&mut builder, &message_wires, actual_bytes, 1024);

	let circuit = builder.build();
	let stats = CircuitStat::collect(&circuit);

	assert!(stats.n_and_constraints > 0);
	assert_eq!(stats.n_mul_constraints, 0, "Should not use MUL constraints");
}

#[test]
fn test_basic_two_chunks() {
	// Basic test for 2048 bytes (two chunks)
	let mut builder = CircuitBuilder::new();
	let message_wires: Vec<Wire> = (0..256).map(|_| builder.add_witness()).collect();
	let actual_bytes = builder.add_witness();
	let _result = blake3_hash(&mut builder, &message_wires, actual_bytes, 2048);

	let circuit = builder.build();
	let stats = CircuitStat::collect(&circuit);

	// Based on POC report, should be around 37,998 AND constraints
	assert!(stats.n_and_constraints < 40000, "Too many AND constraints");
	assert_eq!(stats.n_mul_constraints, 0, "Should not use MUL constraints");
}

#[test]
fn test_maximum_supported_input() {
	// Test current maximum supported size (2048 bytes)
	let mut builder = CircuitBuilder::new();
	let message_wires: Vec<Wire> = (0..256).map(|_| builder.add_witness()).collect();
	let actual_bytes = builder.add_witness();
	let _result = blake3_hash(&mut builder, &message_wires, actual_bytes, 2048);

	let circuit = builder.build();
	let stats = CircuitStat::collect(&circuit);

	assert!(stats.n_and_constraints > 0);
	assert_eq!(stats.n_mul_constraints, 0);
}
