use num_bigint::BigUint;
use quickcheck::TestResult;
use quickcheck_macros::quickcheck;

use super::*;
use crate::{
	compiler::{CircuitBuilder, WitnessFiller},
	constraint_verifier::verify_constraints,
	word::Word,
};

/// Convert witness BigNum to BigUint for computation.
///
/// This function is used during witness generation to extract the actual
/// numeric value from a bignum represented as wires in the circuit.
///
/// # Arguments
/// * `bignum` - The `BigNum` to covert
/// * `w` - Witness filler containing the actual values
///
/// # Returns
/// The bignum value as a `BigUint`
pub fn bignum_to_biguint(bignum: &BigNum, w: &WitnessFiller) -> BigUint {
	let limb_vals: Vec<_> = bignum.limbs.iter().map(|&l| w[l].as_u64()).collect();
	from_u64_limbs(limb_vals)
}

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

	let a = BigNum::new_witness(&builder, num_limbs);
	let b = BigNum::new_witness(&builder, num_limbs);

	let result = add(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set input values
	for (i, &(a_val, b_val)) in vals.iter().enumerate() {
		w[a.limbs[i]] = Word(a_val);
		w[b.limbs[i]] = Word(b_val);
	}

	cs.populate_wire_witness(&mut w).unwrap();

	// Compare result with expected
	for i in 0..num_limbs {
		if w[result.limbs[i]] != Word(expected[i]) {
			return TestResult::error(format!(
				"Result Limb {} mismatch: got {}, expected {}",
				i, w[result.limbs[i]].0, expected[i]
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

	let a = BigNum {
		limbs: vec![builder.add_witness()],
	};
	let b = BigNum {
		limbs: vec![builder.add_witness()],
	};

	add(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set both to MAX - this will overflow a single limb
	w[a.limbs[0]] = Word(u64::MAX);
	w[b.limbs[0]] = Word(u64::MAX);

	// This should fail due to the final carry check
	let result = cs.populate_wire_witness(&mut w);
	assert!(result.is_err());
}

#[test]
fn test_mul_single_case() {
	let builder = CircuitBuilder::new();

	// Create 2048-bit numbers for inputs (32 limbs)
	let a = BigNum::new_witness(&builder, 32);
	let b = BigNum::new_witness(&builder, 32);

	let mul = mul(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set inputs: a = 2^64 + 1, b = 2^64 + 2
	// a.limbs[0] = 1, a.limbs[1] = 1, rest = 0
	// b.limbs[0] = 2, b.limbs[1] = 1, rest = 0
	w[a.limbs[0]] = Word(1);
	w[a.limbs[1]] = Word(1);
	for i in 2..32 {
		w[a.limbs[i]] = Word(0);
	}

	w[b.limbs[0]] = Word(2);
	w[b.limbs[1]] = Word(1);
	for i in 2..32 {
		w[b.limbs[i]] = Word(0);
	}

	// Run the circuit to verify all constraints
	cs.populate_wire_witness(&mut w).unwrap();

	// Expected result: (2^64 + 1) * (2^64 + 2) = 2^128 + 3*2^64 + 2
	// result[0] = 2
	// result[1] = 3
	// result[2] = 1
	// rest = 0
	assert_eq!(w[mul.limbs[0]], Word(2));
	assert_eq!(w[mul.limbs[1]], Word(3));
	assert_eq!(w[mul.limbs[2]], Word(1));
	for i in 3..64 {
		assert_eq!(w[mul.limbs[i]], Word(0));
	}

	// Verify all constraints are satisfied
	verify_constraints(&cs.constraint_system(), &w.into_value_vec()).unwrap();
}

#[quickcheck]
fn test_mul_with_values(a_limbs: Vec<u64>, b_limbs: Vec<u64>) -> TestResult {
	let builder = CircuitBuilder::new();

	let a = BigNum::new_inout(&builder, a_limbs.len());
	let b = BigNum::new_inout(&builder, b_limbs.len());

	let result = mul(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	for (i, &val) in a_limbs.iter().enumerate() {
		w[a.limbs[i]] = Word(val);
	}
	for (i, &val) in b_limbs.iter().enumerate() {
		w[b.limbs[i]] = Word(val);
	}

	let a_big = from_u64_limbs(a_limbs);
	let b_big = from_u64_limbs(b_limbs);
	let expected = &a_big * &b_big;

	cs.populate_wire_witness(&mut w).unwrap();

	let result_big = bignum_to_biguint(&result, &w);

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

	let a = BigNum::new_witness(&builder, a_limbs.len());
	let result = square(&builder, &a);

	let cs = builder.build();

	let mut w = cs.new_witness_filler();
	for (i, &val) in a_limbs.iter().enumerate() {
		w[a.limbs[i]] = Word(val);
	}

	let a_big = from_u64_limbs(a_limbs);
	let expected = &a_big * &a_big;

	cs.populate_wire_witness(&mut w).unwrap();

	let result_big = bignum_to_biguint(&result, &w);

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

	let a = BigNum::new_witness(&builder, vals.len());

	let square_result = square(&builder, &a);
	let mul_result = mul(&builder, &a, &a);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	for (i, &val) in vals.iter().enumerate() {
		w[a.limbs[i]] = Word(val);
	}

	cs.populate_wire_witness(&mut w).unwrap();

	let square_big = bignum_to_biguint(&square_result, &w);
	let mul_big = bignum_to_biguint(&mul_result, &w);

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
	let a = BigNum::new_witness(&builder, vals.len());
	let b = BigNum::new_witness(&builder, vals.len());

	let result = compare(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	// Set same values for both inputs
	for (i, &val) in vals.iter().enumerate() {
		w[a.limbs[i]] = Word(val);
		w[b.limbs[i]] = Word(val);
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
	let a = BigNum::new_witness(&builder, a_vals.len());
	let b = BigNum::new_witness(&builder, b_vals.len());

	let result = compare(&builder, &a, &b);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	for (i, &val) in a_vals.iter().enumerate() {
		w[a.limbs[i]] = Word(val);
	}
	for (i, &val) in b_vals.iter().enumerate() {
		w[b.limbs[i]] = Word(val);
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

#[test]
fn test_mod_reduce() {
	let builder = CircuitBuilder::new();

	let a = BigNum {
		limbs: vec![
			builder.add_witness(),
			builder.add_witness(),
			builder.add_witness(),
		],
	};
	let modulus = BigNum {
		limbs: vec![builder.add_witness(), builder.add_witness()],
	};

	let (quotient, remainder) = mod_reduce(&builder, &a, &modulus);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	w[a.limbs[0]] = Word(0x0F1E2D3C4B5A6978);
	w[a.limbs[1]] = Word(0xFEDCBA9876543210);
	w[a.limbs[2]] = Word(0x123456789ABCDEF0);

	w[modulus.limbs[0]] = Word(0x2222222222222222);
	w[modulus.limbs[1]] = Word(0x1111111111111111);

	cs.populate_wire_witness(&mut w).unwrap();

	assert_eq!(w[quotient.limbs[0]].as_u64(), 0x111111111111101d, "Quotient limb 0 mismatch");
	assert_eq!(w[quotient.limbs[1]].as_u64(), 0x0000000000000001, "Quotient limb 1 mismatch");
	assert_eq!(w[quotient.limbs[2]].as_u64(), 0x0000000000000000, "Quotient limb 2 mismatch");
	assert_eq!(w[remainder.limbs[0]].as_u64(), 0x77cb1e71c5186b9e, "Remainder limb 0 mismatch");
	assert_eq!(w[remainder.limbs[1]].as_u64(), 0x0eca8641fdb97541, "Remainder limb 1 mismatch");

	let a_big = bignum_to_biguint(&a, &w);
	let modulus_big = bignum_to_biguint(&modulus, &w);
	let actual_quotient = bignum_to_biguint(&quotient, &w);
	let actual_remainder = bignum_to_biguint(&remainder, &w);

	let reconstructed = &actual_quotient * &modulus_big + &actual_remainder;
	assert_eq!(reconstructed, a_big, "Reconstruction mismatch");

	verify_constraints(&cs.constraint_system(), &w.into_value_vec()).unwrap();
}

#[quickcheck]
fn prop_mod_reduce(a_vals: Vec<u64>, mod_vals: Vec<u64>) -> TestResult {
	if mod_vals.len() > a_vals.len() {
		return TestResult::discard();
	}

	if mod_vals.iter().all(|&v| v == 0) {
		return TestResult::discard();
	}

	let builder = CircuitBuilder::new();
	let a = BigNum::new_witness(&builder, a_vals.len());
	let modulus = BigNum::new_witness(&builder, mod_vals.len());

	let (quotient, remainder) = mod_reduce(&builder, &a, &modulus);

	let cs = builder.build();
	let mut w = cs.new_witness_filler();

	for (i, &val) in a_vals.iter().enumerate() {
		w[a.limbs[i]] = Word(val);
	}
	for (i, &val) in mod_vals.iter().enumerate() {
		w[modulus.limbs[i]] = Word(val);
	}

	if let Err(e) = cs.populate_wire_witness(&mut w) {
		return TestResult::error(format!("Circuit execution failed: {e:?}"));
	}

	let a_big = bignum_to_biguint(&a, &w);
	let modulus_big = bignum_to_biguint(&modulus, &w);
	let quotient_big = bignum_to_biguint(&quotient, &w);
	let remainder_big = bignum_to_biguint(&remainder, &w);

	let reconstructed = &quotient_big * &modulus_big + &remainder_big;
	if reconstructed != a_big {
		return TestResult::error(format!(
			"ModReduce failed: {a_big} != {quotient_big} * {modulus_big} + {remainder_big}"
		));
	}

	if let Err(e) = verify_constraints(&cs.constraint_system(), &w.into_value_vec()) {
		return TestResult::error(format!("Constraint verification failed: {e:?}"));
	}

	TestResult::passed()
}
