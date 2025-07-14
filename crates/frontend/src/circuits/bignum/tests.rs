use quickcheck::TestResult;
use quickcheck_macros::quickcheck;

use super::*;
use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints, word::Word};

#[quickcheck]
fn prop_add_multi_limb(vals: Vec<(u64, u64)>) -> TestResult {
	// Test multi-limb addition with carry propagation
	if vals.len() > 16 {
		return TestResult::discard();
	}

	// Pre-compute to check for overflow
	let mut carry = 0u64;
	let mut expected = vec![0u64; vals.len()];
	for (i, &(a_val, b_val)) in vals.iter().enumerate() {
		let (sum1, overflow1) = a_val.overflowing_add(b_val);
		let (sum2, overflow2) = sum1.overflowing_add(carry);
		expected[i] = sum2;
		carry = (overflow1 as u64) + (overflow2 as u64);
	}

	// Discard any test values that would overflow, as these are not
	// supported by the circuit constraints.
	if carry > 0 {
		return TestResult::discard();
	}

	let builder = CircuitBuilder::new();
	let num_limbs = vals.len();

	let a: Vec<Wire> = (0..num_limbs).map(|_| builder.add_witness()).collect();
	let b: Vec<Wire> = (0..num_limbs).map(|_| builder.add_witness()).collect();

	let result = add(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set input values
	for (i, &(a_val, b_val)) in vals.iter().enumerate() {
		w[a[i]] = Word(a_val);
		w[b[i]] = Word(b_val);
	}

	cs.populate_wire_witness(&mut w).unwrap();

	// Compare result with expected
	for i in 0..num_limbs {
		if w[result[i]] != Word(expected[i]) {
			return TestResult::error(format!(
				"Result Limb {} mismatch: got {}, expected {}",
				i, w[result[i]].0, expected[i]
			));
		}
	}

	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}

#[test]
fn test_add_overflow_detection_via_final_carry() {
	// This test demonstrates that the final carry check catches overflow
	// We'll try to add values that would overflow the allocated limbs
	let builder = CircuitBuilder::new();

	let a = vec![builder.add_witness()];
	let b = vec![builder.add_witness()];

	add(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set both to MAX - this will overflow a single limb
	w[a[0]] = Word(u64::MAX);
	w[b[0]] = Word(u64::MAX);

	// This should fail due to the final carry check
	let result = cs.populate_wire_witness(&mut w);
	assert!(result.is_err());
}

#[test]
fn test_mul_single_case() {
	let builder = CircuitBuilder::new();

	// Create 2048-bit numbers for inputs (32 limbs)
	let a: Vec<Wire> = (0..32).map(|_| builder.add_witness()).collect();
	let b: Vec<Wire> = (0..32).map(|_| builder.add_witness()).collect();

	let mul = mul(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set inputs: a = 2^64 + 1, b = 2^64 + 2
	// a[0] = 1, a[1] = 1, rest = 0
	// b[0] = 2, b[1] = 1, rest = 0
	w[a[0]] = Word(1);
	w[a[1]] = Word(1);
	for i in 2..32 {
		w[a[i]] = Word(0);
	}

	w[b[0]] = Word(2);
	w[b[1]] = Word(1);
	for i in 2..32 {
		w[b[i]] = Word(0);
	}

	// Run the circuit to verify all constraints
	cs.populate_wire_witness(&mut w).unwrap();

	// Expected result: (2^64 + 1) * (2^64 + 2) = 2^128 + 3*2^64 + 2
	// result[0] = 2
	// result[1] = 3
	// result[2] = 1
	// rest = 0
	assert_eq!(w[mul[0]], Word(2));
	assert_eq!(w[mul[1]], Word(3));
	assert_eq!(w[mul[2]], Word(1));
	for i in 3..64 {
		assert_eq!(w[mul[i]], Word(0));
	}

	// Verify all constraints are satisfied
	verify_constraints(&cs.constraint_system(), &w.into_value_vec()).unwrap();
}

#[quickcheck]
fn test_mul_with_values(a_limbs: Vec<u64>, b_limbs: Vec<u64>) -> TestResult {
	let builder = CircuitBuilder::new();

	let a: Vec<Wire> = (0..a_limbs.len()).map(|_| builder.add_witness()).collect();
	let b: Vec<Wire> = (0..b_limbs.len()).map(|_| builder.add_witness()).collect();

	let result = mul(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	for (i, &val) in a_limbs.iter().enumerate() {
		w[a[i]] = Word(val);
	}
	for (i, &val) in b_limbs.iter().enumerate() {
		w[b[i]] = Word(val);
	}

	let a_big = biguint_from_u64_slice(&a_limbs);
	let b_big = biguint_from_u64_slice(&b_limbs);
	let expected = &a_big * &b_big;

	cs.populate_wire_witness(&mut w).unwrap();

	let result_big = limbs_to_biguint(&result, &w);

	if result_big != expected {
		return TestResult::error(format!(
			"Multiplication failed: {a_big} * {b_big} = {result_big} (expected {expected})"
		));
	}

	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}

#[quickcheck]
fn test_square_with_values(a_limbs: Vec<u64>) -> TestResult {
	let builder = CircuitBuilder::new();

	let a: Vec<Wire> = (0..a_limbs.len()).map(|_| builder.add_witness()).collect();
	let result = square(&builder, &a);

	let cs = builder.build();

	let mut w = cs.new_witness_filler();
	for (i, &val) in a_limbs.iter().enumerate() {
		w[a[i]] = Word(val);
	}

	let a_big = biguint_from_u64_slice(&a_limbs);
	let expected = &a_big * &a_big;

	cs.populate_wire_witness(&mut w).unwrap();

	let result_big = limbs_to_biguint(&result, &w);

	if result_big != expected {
		return TestResult::error(format!(
			"Squaring failed: {a_big}^2 = {result_big} (expected {expected})"
		));
	}

	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}

#[quickcheck]
fn prop_square_vs_mul_equivalence(vals: Vec<u64>) -> TestResult {
	if vals.is_empty() || vals.len() > 8 {
		return TestResult::discard();
	}

	let builder = CircuitBuilder::new();

	let a: Vec<Wire> = (0..vals.len()).map(|_| builder.add_witness()).collect();

	let square_result = square(&builder, &a);
	let mul_result = mul(&builder, &a, &a);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	for (i, &val) in vals.iter().enumerate() {
		w[a[i]] = Word(val);
	}

	cs.populate_wire_witness(&mut w).unwrap();

	let square_big = limbs_to_biguint(&square_result, &w);
	let mul_big = limbs_to_biguint(&mul_result, &w);

	if square_big != mul_big {
		return TestResult::error(format!("square(a) != mul(a,a): {square_big} != {mul_big}"));
	}

	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}

#[quickcheck]
fn prop_compare_equal(vals: Vec<u64>) -> TestResult {
	if vals.len() > 8 {
		return TestResult::discard();
	}

	let builder = CircuitBuilder::new();
	let a: Vec<Wire> = (0..vals.len()).map(|_| builder.add_witness()).collect();
	let b: Vec<Wire> = (0..vals.len()).map(|_| builder.add_witness()).collect();

	let result = compare(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set same values for both inputs
	for (i, &val) in vals.iter().enumerate() {
		w[a[i]] = Word(val);
		w[b[i]] = Word(val);
	}

	cs.populate_wire_witness(&mut w).unwrap();

	// Should be equal (all 1s)
	if w[result] != Word(u64::MAX) {
		return TestResult::error("Result is not all 1s");
	}

	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}

#[quickcheck]
fn prop_compare_different(a_vals: Vec<u64>, b_vals: Vec<u64>) -> TestResult {
	if a_vals.len() != b_vals.len() || a_vals.len() > 8 {
		return TestResult::discard();
	}

	// Skip if they're actually equal
	if a_vals == b_vals {
		return TestResult::discard();
	}

	let builder = CircuitBuilder::new();
	let a: Vec<Wire> = (0..a_vals.len()).map(|_| builder.add_witness()).collect();
	let b: Vec<Wire> = (0..b_vals.len()).map(|_| builder.add_witness()).collect();

	let result = compare(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	for (i, &val) in a_vals.iter().enumerate() {
		w[a[i]] = Word(val);
	}
	for (i, &val) in b_vals.iter().enumerate() {
		w[b[i]] = Word(val);
	}

	// Run the circuit - this might fail for some cases
	if let Err(e) = cs.populate_wire_witness(&mut w) {
		return TestResult::error(format!("Circuit execution failed: {e:?}"));
	}

	// Should be not equal (all 0s)
	if w[result] != Word(0) {
		return TestResult::error("Different values detected as equal".to_string());
	}

	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}

#[quickcheck]
fn prop_mod_reduce_multi_limb(a_val: u64, b_val: u64, mod_val: u32) -> TestResult {
	// Skip if modulus is zero
	if mod_val == 0 {
		return TestResult::discard();
	}

	// Create a 4-limb dividend from two u64 values
	let dividend_limbs = [a_val, b_val, 0, 0];
	let modulus_limbs = [mod_val as u64, 0];

	let builder = CircuitBuilder::new();

	// Create witness wires (4 limbs for dividend, 2 for modulus)
	let a: Vec<Wire> = (0..4).map(|_| builder.add_witness()).collect();
	let modulus: Vec<Wire> = (0..2).map(|_| builder.add_witness()).collect();

	// Create ModReduce circuit
	let mod_reduce = ModReduce::new(&builder, a.clone(), modulus.clone());

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set input values
	for (i, &val) in dividend_limbs.iter().enumerate() {
		w[a[i]] = Word(val);
	}

	for (i, &val) in modulus_limbs.iter().enumerate() {
		w[modulus[i]] = Word(val);
	}

	// Populate quotient and remainder
	mod_reduce.populate_result(&mut w);

	// Run the circuit
	if let Err(e) = cs.populate_wire_witness(&mut w) {
		return TestResult::error(format!("Circuit execution failed: {e:?}"));
	}

	// Verify mathematical correctness using BigUint
	let a_val = limbs_to_biguint(&mod_reduce.a, &w);
	let mod_val = limbs_to_biguint(&mod_reduce.modulus, &w);
	let q_val = limbs_to_biguint(&mod_reduce.quotient, &w);
	let r_val = limbs_to_biguint(&mod_reduce.remainder, &w);

	// Check: a = q * modulus + r
	let reconstructed = &q_val * &mod_val + &r_val;
	if a_val != reconstructed {
		return TestResult::error(format!(
			"Division property failed: {a_val} != {q_val} * {mod_val} + {r_val}"
		));
	}

	// Check: r < modulus
	if r_val >= mod_val {
		return TestResult::error(format!("Remainder {r_val} >= modulus {mod_val}"));
	}

	// Verify all constraints are satisfied
	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}
