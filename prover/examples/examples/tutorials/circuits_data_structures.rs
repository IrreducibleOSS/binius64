// Copyright 2025 Irreducible Inc.

//! Data Structures Example
//!
//! This example shows:
//! - Pre-allocated concatenation patterns
//! - Constraint-based verification
//! - Fixed-size data structures
//!
//! Guide: https://www.binius.xyz/building/

use anyhow::Result;
use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::CircuitBuilder;

fn main() -> Result<()> {
	println!("=== Data Structures Example ===\n");

	demo_concatenation()?;

	Ok(())
}

fn demo_concatenation() -> Result<()> {
	println!("Concatenation Without Dynamic Allocation\n");

	let builder = CircuitBuilder::new();

	// Two 4-element arrays
	let data_a: [_; 4] = core::array::from_fn(|_| builder.add_witness());
	let data_b: [_; 4] = core::array::from_fn(|_| builder.add_witness());

	// Pre-allocated joined array
	let joined: [_; 8] = core::array::from_fn(|_| builder.add_witness());

	// Verify joined = data_a || data_b
	for i in 0..4 {
		builder.assert_eq(format!("concat_a[{i}]"), joined[i], data_a[i]);
		builder.assert_eq(format!("concat_b[{i}]"), joined[i + 4], data_b[i]);
	}

	let circuit = builder.build();

	let mut w = circuit.new_witness_filler();

	// Set witness values
	for (i, &wire) in data_a.iter().enumerate() {
		w[wire] = Word((i + 1) as u64 * 10);
	}
	for (i, &wire) in data_b.iter().enumerate() {
		w[wire] = Word((i + 5) as u64 * 10);
	}
	for (i, &wire) in joined.iter().enumerate() {
		w[wire] = Word((i + 1) as u64 * 10);
	}

	circuit.populate_wire_witness(&mut w)?;
	let cs = circuit.constraint_system();
	verify_constraints(cs, &w.into_value_vec()).map_err(|e| anyhow::anyhow!(e))?;

	println!("✓ Concatenation verified: [10,20,30,40] || [50,60,70,80]");
	println!("  Constraints enforce joined = data_a || data_b\n");

	Ok(())
}
