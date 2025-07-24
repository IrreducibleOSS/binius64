use proptest::prelude::*;
use rand::{Rng, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{constraint_verifier::verify_constraints, uniqueness_propagator::process_circuit_uniqueness, word::Word};

#[test]
fn wires_layout() {
	// Create a circuit with wires in mixed order
	let builder = CircuitBuilder::new();

	// Add wires in a specific order to test sorting
	let witness1 = builder.add_witness();
	let const1 = builder.add_constant(Word(42));
	let internal1 = builder.add_internal();
	let inout1 = builder.add_inout();
	let witness2 = builder.add_witness();
	let _const2 = builder.add_constant(Word(100));
	let inout2 = builder.add_inout();
	let witness3 = builder.add_witness();
	let _const3 = builder.add_constant(Word(200));

	// Build the circuit to trigger wire sorting
	let circuit = builder.build();

	// Verify that wire mapping follows the expected order: const, inout, witness
	// Expected final order:
	//
	//     1. const1(42),
	//     2. const2(100),
	//     3. const3(200),
	//     4. inout1,
	//     5. inout2,
	//     6. witness1,
	//     7. witness2,
	//     8. witness3
	//     9. internal1
	//

	// Constants should come first - verify const1 is at position 0
	assert_eq!(circuit.witness_index(const1), ValueIndex(0));

	// Inout wires should come after constants
	// inout1 (Wire(2)) should be the first inout wire
	let inout1_idx = circuit.witness_index(inout1);
	// inout2 (Wire(5)) should be the second inout wire
	let inout2_idx = circuit.witness_index(inout2);

	// Witness wires should come after
	let witness1_idx = circuit.witness_index(witness1);
	let witness2_idx = circuit.witness_index(witness2);
	let witness3_idx = circuit.witness_index(witness3);

	let internal1_idx = circuit.witness_index(internal1);

	// Verify ordering: all constants < all inouts < all witnesses < all internal
	assert!(inout1_idx.0 > circuit.witness_index(const1).0);
	assert!(inout2_idx.0 > inout1_idx.0);
	assert!(witness1_idx.0 > inout1_idx.0);
	assert!(witness1_idx.0 > inout2_idx.0);
	assert!(witness2_idx.0 > inout1_idx.0);
	assert!(witness2_idx.0 > inout2_idx.0);
	assert!(witness3_idx.0 > inout1_idx.0);
	assert!(witness3_idx.0 > inout2_idx.0);
	assert!(internal1_idx.0 > witness2_idx.0);

	// Verify that witness wires maintain their relative order
	assert!(witness2_idx.0 > witness1_idx.0);
	assert!(witness3_idx.0 > witness2_idx.0);

	// Verify that inout wires maintain their relative order
	assert!(inout2_idx.0 > inout1_idx.0);

	// Verify that witness start with a power-of-two index.
	assert!(witness1_idx.0.is_power_of_two(), "witness values must start with a po2 index");
}

#[test]
fn test_icmp_ult() {
	// Build a circuit with only two inputs and check c = a < b.
	let builder = CircuitBuilder::new();
	let a = builder.add_inout();
	let b = builder.add_inout();
	let actual = builder.icmp_ult(a, b);
	let expected = builder.add_inout();
	builder.assert_eq("lt", actual, expected);
	let circuit = builder.build();

	// check that it actually works.
	let mut rng = StdRng::seed_from_u64(42);
	for _ in 0..10000 {
		let mut w = circuit.new_witness_filler();
		w[a] = Word(rng.random::<u64>());
		w[b] = Word(rng.random::<u64>());
		w[expected] = Word(if w[a].0 < w[b].0 { u64::MAX } else { 0 });
		w.circuit.populate_wire_witness(&mut w).unwrap();
	}
}

#[test]
fn test_icmp_eq() {
	// Build a circuit with only two inputs and check c = a == b.
	let builder = CircuitBuilder::new();
	let a = builder.add_inout();
	let b = builder.add_inout();
	let actual = builder.icmp_eq(a, b);
	let expected = builder.add_inout();
	builder.assert_eq("eq", actual, expected);
	let circuit = builder.build();

	// check that it actually works.
	let mut rng = StdRng::seed_from_u64(42);
	for _ in 0..10000 {
		let mut w = circuit.new_witness_filler();
		w[a] = Word(rng.random::<u64>());
		w[b] = Word(rng.random::<u64>());
		w[expected] = Word(if w[a].0 == w[b].0 { u64::MAX } else { 0 });
		w.circuit.populate_wire_witness(&mut w).unwrap();
	}
}

#[test]
fn test_iadd_cin_cout_max_values() {
	let builder = CircuitBuilder::new();

	let a = builder.add_constant_64(0xFFFFFFFFFFFFFFFF);
	let b = builder.add_constant_64(0xFFFFFFFFFFFFFFFF);
	let cin_wire = builder.add_constant(Word::ZERO);
	let (sum_wire, cout_wire) = builder.iadd_cin_cout(a, b, cin_wire);

	let circuit = builder.build();
	let mut w = circuit.new_witness_filler();
	circuit.populate_wire_witness(&mut w).unwrap();

	assert_eq!(w[sum_wire], Word(0xFFFFFFFFFFFFFFFE));
	assert_eq!(w[cout_wire], Word(0xFFFFFFFFFFFFFFFF));
}

#[test]
fn test_iadd_cin_cout_zero() {
	let builder = CircuitBuilder::new();

	let a = builder.add_constant_64(0);
	let b = builder.add_constant_64(0);
	let cin_wire = builder.add_constant(Word::ZERO);
	let (sum_wire, cout_wire) = builder.iadd_cin_cout(a, b, cin_wire);

	let circuit = builder.build();
	let mut w = circuit.new_witness_filler();
	circuit.populate_wire_witness(&mut w).unwrap();

	assert_eq!(w[sum_wire], Word(0));
	assert_eq!(w[cout_wire], Word(0));
}

fn prop_check_icmp_ult(a: u64, b: u64, expected_result: Word) {
	let builder = CircuitBuilder::new();
	let a_wire = builder.add_constant_64(a);
	let b_wire = builder.add_constant_64(b);
	let result_wire = builder.icmp_ult(a_wire, b_wire);

	let circuit = builder.build();
	let mut w = circuit.new_witness_filler();
	circuit.populate_wire_witness(&mut w).unwrap();

	assert_eq!(w[result_wire], expected_result);

	let cs = circuit.constraint_system();
	verify_constraints(&cs, &w.value_vec).unwrap();
}

fn prop_check_icmp_eq(a: u64, b: u64, expected_result: Word) {
	let builder = CircuitBuilder::new();
	let a_wire = builder.add_constant_64(a);
	let b_wire = builder.add_constant_64(b);
	let result_wire = builder.icmp_eq(a_wire, b_wire);

	let circuit = builder.build();
	let mut w = circuit.new_witness_filler();
	circuit.populate_wire_witness(&mut w).unwrap();

	assert_eq!(w[result_wire], expected_result);

	let cs = circuit.constraint_system();
	verify_constraints(&cs, &w.value_vec).unwrap();
}

proptest! {
	#[test]
	fn prop_iadd_cin_cout_carry_chain(a1 in any::<u64>(), b1 in any::<u64>(), a2 in any::<u64>(), b2 in any::<u64>()) {
		let builder = CircuitBuilder::new();

		// First addition
		let a1_wire = builder.add_constant_64(a1);
		let b1_wire = builder.add_constant_64(b1);
		let cin_wire = builder.add_constant(Word::ZERO);
		let (sum1_wire, cout1_wire) = builder.iadd_cin_cout(a1_wire, b1_wire, cin_wire);

		// Second addition with carry from first
		let a2_wire = builder.add_constant_64(a2);
		let b2_wire = builder.add_constant_64(b2);
		let (sum2_wire, cout2_wire) = builder.iadd_cin_cout(a2_wire, b2_wire, cout1_wire);

		let circuit = builder.build();
		let mut w = circuit.new_witness_filler();
		circuit.populate_wire_witness(&mut w).unwrap();

		// Check first addition
		let expected_sum1 = a1.wrapping_add(b1);
		let expected_cout1 = (a1 & b1) | ((a1 ^ b1) & !expected_sum1);
		assert_eq!(w[sum1_wire], Word(expected_sum1));
		assert_eq!(w[cout1_wire], Word(expected_cout1));

		// Check second addition with carry
		// Extract MSB of cout1 as the carry-in bit
		let cin2 = expected_cout1 >> 63;
		let expected_sum2 = a2.wrapping_add(b2).wrapping_add(cin2);
		let expected_cout2 = (a2 & b2) | ((a2 ^ b2) & !expected_sum2);
		assert_eq!(w[sum2_wire], Word(expected_sum2));
		assert_eq!(w[cout2_wire], Word(expected_cout2));

		let cs = circuit.constraint_system();
		verify_constraints(&cs, &w.value_vec).unwrap();
	}

	#[test]
	fn prop_icmp_ult_gte(a in any::<u64>(), b in any::<u64>()) {
		prop_assume!(a >= b);
		prop_check_icmp_ult(a, b, Word::ZERO);
	}

	#[test]
	fn prop_icmp_ult_lt(a in any::<u64>(), b in any::<u64>()) {
		prop_assume!(a < b);
		prop_check_icmp_ult(a, b, Word::ALL_ONE);
	}

	#[test]
	fn prop_check_assert_eq(x in any::<u64>(), y in any::<u64>()) {
		let builder = CircuitBuilder::new();
		let is_equal = x == y;
		let x_wire = builder.add_constant_64(x);
		let y_wire = builder.add_constant_64(y);
		builder.assert_eq("eq", x_wire, y_wire);

		let circuit = builder.build();
		let mut w = circuit.new_witness_filler();

		let result = circuit.populate_wire_witness(&mut w);

		if is_equal {
			// When values are equal, witness population should succeed
			assert!(result.is_ok());
			// And constraints should verify
			let cs = circuit.constraint_system();
			verify_constraints(&cs, &w.value_vec).unwrap();
		} else {
			// When values are not equal, witness population should fail
			assert!(result.is_err());
		}
	}

	#[test]
	fn prop_icmp_eq_equal(a in any::<u64>()) {
		prop_check_icmp_eq(a, a, Word::ALL_ONE);
	}

	#[test]
	fn prop_icmp_eq_not_equal(a in any::<u64>(), b in any::<u64>()) {
		prop_assume!(a != b);
		prop_check_icmp_eq(a, b, Word::ZERO);
	}
}
