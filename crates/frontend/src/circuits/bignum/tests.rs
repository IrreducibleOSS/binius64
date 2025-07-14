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
