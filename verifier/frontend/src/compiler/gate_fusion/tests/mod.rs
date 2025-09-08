// Copyright 2025 Irreducible Inc.
mod awhole;
mod commit_set;

use crate::{
	circuits::keccak::permutation::Permutation,
	compiler::{CircuitBuilder, Options, Wire},
};

#[test]
fn keccak() {
	let builder = CircuitBuilder::with_opts(Options {
		enable_gate_fusion: true,
		enable_constant_propagation: false,
	});
	let initial_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());
	let expected_final_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());
	let mut computed_state = initial_state;
	Permutation::keccak_f1600(&builder, &mut computed_state);
	builder.assert_eq_v("final_state", computed_state, expected_final_state);
	let _ = builder.build();
}

#[test]
fn keccak_single_round() {
	let builder = CircuitBuilder::with_opts(Options {
		enable_gate_fusion: true,
		enable_constant_propagation: false,
	});

	let initial_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());
	let expected_final_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());
	let mut computed_state = initial_state;

	// Run just one round of Keccak
	Permutation::keccak_permutation_round(&builder, &mut computed_state, 0);

	builder.assert_eq_v("final_state", computed_state, expected_final_state);
	let _ = builder.build();
}

#[test]
fn keccak_two_rounds() {
	let builder = CircuitBuilder::with_opts(Options {
		enable_gate_fusion: true,
		enable_constant_propagation: false,
	});

	let initial_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());
	let expected_final_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());
	let mut computed_state = initial_state;

	// Run exactly 2 rounds of Keccak
	Permutation::keccak_permutation_round(&builder, &mut computed_state, 0);
	eprintln!("\n=== Round 1 output state (these become inputs to round 2) ===");
	for (i, &wire) in computed_state.iter().enumerate() {
		if i < 5 {
			eprintln!("  computed_state[{}] = {:?}", i, wire);
		}
	}
	Permutation::keccak_permutation_round(&builder, &mut computed_state, 1);

	builder.assert_eq_v("final_state", computed_state, expected_final_state);
	let _ = builder.build();
}
