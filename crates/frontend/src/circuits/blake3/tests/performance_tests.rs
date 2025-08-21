use std::time::Instant;

use binius_core::word::Word;

use super::super::{compress, g_function, *};
use crate::{compiler::CircuitBuilder, stat::CircuitStat};

/// Verify single block constraint count meets target
#[test]
fn test_single_block_constraints() {
	let mut builder = CircuitBuilder::new();
	let _blake3 = blake3_hash_witness(&mut builder, 64);
	let circuit = builder.build();

	let stats = CircuitStat::collect(&circuit);

	println!("Blake3 Single Block (64 bytes) Constraint Statistics:");
	println!("================================================");
	println!("{}", stats);
	println!("Target: <1,200 AND constraints");
	println!("Actual: {} AND constraints", stats.n_and_constraints);
	println!("Efficiency: {:.1}%", (1200.0 - stats.n_and_constraints as f64) / 12.0);

	assert!(
		stats.n_and_constraints <= 1200,
		"Single block Blake3 exceeds target: {} AND constraints (target: <1,200)",
		stats.n_and_constraints
	);

	assert_eq!(stats.n_mul_constraints, 0, "Blake3 should not use MUL constraints");
}

/// Test constraint scaling with different input sizes
#[test]
fn test_constraint_scaling() {
	let test_sizes = vec![8, 16, 32, 64, 128, 256];

	println!("\nBlake3 Constraint Scaling Analysis:");
	println!("====================================");
	println!("Max Size | AND Constraints | AND/byte | Gates | Wires");
	println!("---------|-----------------|----------|-------|------");

	for size in test_sizes {
		let mut builder = CircuitBuilder::new();
		let _blake3 = blake3_hash_witness(&mut builder, size);
		let circuit = builder.build();

		let stats = CircuitStat::collect(&circuit);
		let and_per_byte = stats.n_and_constraints as f64 / size as f64;

		println!(
			"{:8} | {:15} | {:8.2} | {:5} | {:5}",
			size, stats.n_and_constraints, and_per_byte, stats.n_gates, stats.value_vec_len
		);

		// Single block sizes should all have similar constraints
		if size <= 64 {
			assert!(
				stats.n_and_constraints <= 1200,
				"Size {} uses too many constraints: {}",
				size,
				stats.n_and_constraints
			);
		}
	}
}

/// Benchmark witness generation performance
#[test]
fn test_witness_generation_performance() {
	let mut builder = CircuitBuilder::new();
	let blake3 = blake3_hash_witness(&mut builder, 64);
	let circuit = builder.build();

	let test_cases = vec![
		(b"".to_vec(), "Empty"),
		(b"a".to_vec(), "Single byte"),
		(vec![0xFFu8; 32], "Half block"),
		(vec![0xAAu8; 64], "Full block"),
	];

	println!("\nWitness Generation Performance:");
	println!("================================");
	println!("Input          | Time (µs) | Throughput");
	println!("---------------|-----------|------------");

	for (message, name) in test_cases {
		let iterations = 1000;
		let start = Instant::now();

		for _ in 0..iterations {
			let mut witness = circuit.new_witness_filler();
			blake3.fill_witness(&mut witness, &message);
			witness[blake3.len] = Word(message.len() as u64);
			let _ = circuit.populate_wire_witness(&mut witness);
		}

		let elapsed = start.elapsed();
		let time_per_iter = elapsed.as_micros() / iterations;
		let throughput = if !message.is_empty() {
			format!(
				"{:.1} MB/s",
				(message.len() as f64 * 1_000_000.0) / (time_per_iter as f64 * 1024.0 * 1024.0)
			)
		} else {
			"N/A".to_string()
		};

		println!("{:14} | {:9} | {}", name, time_per_iter, throughput);
	}
}

/// Test memory efficiency with wire reuse
#[test]
fn test_memory_efficiency() {
	let mut builder = CircuitBuilder::new();
	let _blake3 = blake3_hash_witness(&mut builder, 64);
	let circuit = builder.build();

	let stats = CircuitStat::collect(&circuit);

	println!("\nMemory Efficiency Analysis:");
	println!("===========================");
	println!("Total wires: {}", stats.value_vec_len);
	println!("  - Constants: {}", stats.n_const);
	println!("  - Input/Output: {}", stats.n_inout);
	println!("  - Witness: {}", stats.n_witness);
	println!("  - Internal: {}", stats.n_internal);

	let wire_efficiency = (stats.n_gates as f64) / (stats.value_vec_len as f64);
	println!("Wire efficiency: {:.2} gates/wire", wire_efficiency);

	// Check for reasonable memory usage
	assert!(
		stats.value_vec_len <= 2500,
		"Excessive wire count: {} (expected < 2500)",
		stats.value_vec_len
	);

	// Internal wires should be the majority (indicates computation)
	assert!(stats.n_internal > stats.n_witness, "Too few internal wires - possible inefficiency");
}

/// Compare constraint counts across different components
#[test]
fn test_component_constraints() {
	// Test G-function in isolation
	let mut builder = CircuitBuilder::new();
	let a = builder.add_witness();
	let b = builder.add_witness();
	let c = builder.add_witness();
	let d = builder.add_witness();
	let x = builder.add_witness();
	let y = builder.add_witness();
	let _ = g_function::g_function(&mut builder, a, b, c, d, x, y);
	let g_circuit = builder.build();
	let g_stats = CircuitStat::collect(&g_circuit);

	// Test single round
	let mut builder = CircuitBuilder::new();
	let state = [builder.add_witness(); 16];
	let msg = [builder.add_witness(); 16];
	let _ = g_function::blake3_round(&mut builder, &state, &msg, 0);
	let round_circuit = builder.build();
	let round_stats = CircuitStat::collect(&round_circuit);

	// Test compression function
	let mut builder = CircuitBuilder::new();
	let cv = [builder.add_witness(); 8];
	let block = [builder.add_witness(); 16];
	let counter = builder.add_witness();
	let block_len = builder.add_witness();
	let flags = builder.add_witness();
	let _ = compress::compress(&mut builder, &cv, &block, counter, block_len, flags);
	let compress_circuit = builder.build();
	let compress_stats = CircuitStat::collect(&compress_circuit);

	println!("\nComponent Constraint Breakdown:");
	println!("================================");
	println!("Component          | AND Constraints | Target");
	println!("-------------------|-----------------|--------");
	println!("G-function         | {:15} | 8-10", g_stats.n_and_constraints);
	println!("Single Round (8 G) | {:15} | ~80", round_stats.n_and_constraints);
	println!("Compression (7 R)  | {:15} | <1000", compress_stats.n_and_constraints);

	// Verify relationships
	assert!(
		g_stats.n_and_constraints <= 20,
		"G-function uses too many constraints: {}",
		g_stats.n_and_constraints
	);

	// Round should be roughly 8x G-function
	let expected_round = g_stats.n_and_constraints * 8;
	let round_overhead = round_stats.n_and_constraints as i32 - expected_round as i32;
	assert!(
		round_overhead.abs() < 20,
		"Round overhead too high: {} (expected ~{})",
		round_stats.n_and_constraints,
		expected_round
	);
}

/// Test constraint count stability with deterministic inputs
#[test]
fn test_constraint_determinism() {
	// Run the same circuit build multiple times
	let mut constraint_counts = Vec::new();

	for seed in 0..5 {
		let mut builder = CircuitBuilder::new();
		let blake3 = blake3_hash_witness(&mut builder, 64);
		let circuit = builder.build();

		let stats = CircuitStat::collect(&circuit);
		constraint_counts.push(stats.n_and_constraints);

		// Also test with witness
		let mut witness = circuit.new_witness_filler();
		let message = vec![seed as u8; 32];
		blake3.fill_witness(&mut witness, &message);
		witness[blake3.len] = Word(32);

		let result = circuit.populate_wire_witness(&mut witness);
		assert!(result.is_ok());
	}

	// All runs should have identical constraint counts
	let first_count = constraint_counts[0];
	for (i, &count) in constraint_counts.iter().enumerate() {
		assert_eq!(
			count, first_count,
			"Constraint count not deterministic: run {} had {} vs expected {}",
			i, count, first_count
		);
	}

	println!("\nConstraint Determinism Test: PASSED");
	println!("Consistent constraint count: {}", first_count);
}

/// Performance regression test - ensure constraints don't increase
#[test]
fn test_no_regression() {
	let mut builder = CircuitBuilder::new();
	let _blake3 = blake3_hash_witness(&mut builder, 64);
	let circuit = builder.build();

	let stats = CircuitStat::collect(&circuit);

	// Historical baseline (from current implementation)
	const BASELINE_AND_CONSTRAINTS: usize = 1153;
	const REGRESSION_THRESHOLD: f64 = 1.05; // Allow 5% increase

	let max_allowed = (BASELINE_AND_CONSTRAINTS as f64 * REGRESSION_THRESHOLD) as usize;

	println!("\nPerformance Regression Test:");
	println!("=============================");
	println!("Baseline: {} AND constraints", BASELINE_AND_CONSTRAINTS);
	println!("Current:  {} AND constraints", stats.n_and_constraints);
	println!("Threshold: {} ({}% tolerance)", max_allowed, (REGRESSION_THRESHOLD - 1.0) * 100.0);

	if stats.n_and_constraints > max_allowed {
		panic!(
			"Performance regression detected! Constraints increased from {} to {} (>{} allowed)",
			BASELINE_AND_CONSTRAINTS, stats.n_and_constraints, max_allowed
		);
	} else if stats.n_and_constraints < BASELINE_AND_CONSTRAINTS {
		println!(
			"Performance IMPROVED by {} constraints!",
			BASELINE_AND_CONSTRAINTS - stats.n_and_constraints
		);
	} else {
		println!("Performance maintained at baseline");
	}
}
