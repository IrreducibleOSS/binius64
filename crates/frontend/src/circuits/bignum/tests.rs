use binius_core::word::Word;
use num_integer::Integer;
use proptest::prelude::*;

use super::*;
use crate::{
	compiler::{CircuitBuilder, circuit::WitnessFiller},
	constraint_verifier::verify_constraints,
};

/// Returns a BigUint from u64 limbs with little-endian ordering
fn from_u64_limbs(limbs: &[u64]) -> num_bigint::BigUint {
	let mut bytes = Vec::with_capacity(limbs.len() * 8);
	for &word in limbs {
		bytes.extend_from_slice(&word.to_le_bytes());
	}
	num_bigint::BigUint::from_bytes_le(&bytes)
}

/// Convert witness BigUint to num_bigint::BigUint for computation.
///
/// This function is used during witness generation to extract the actual
/// numeric value from a bignum represented as wires in the circuit.
///
/// # Arguments
/// * `w` - Witness filler containing the actual values
/// * `biguint` - The `BigUint` to convert
///
/// # Returns
/// The `BigUint` value as a `num_biguint::BigUint`
pub fn biguint_to_num_biguint(w: &WitnessFiller, biguint: &BigUint) -> num_bigint::BigUint {
	let limb_vals: Vec<_> = biguint.limbs.iter().map(|&l| w[l].as_u64()).collect();
	from_u64_limbs(&limb_vals)
}

#[test]
fn test_add_overflow_detection_via_final_carry() {
	// This test demonstrates that the final carry check catches overflow
	// We'll try to add values that would overflow the allocated limbs
	let builder = CircuitBuilder::new();

	let a = BigUint {
		limbs: vec![builder.add_witness()],
	};
	let b = BigUint {
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
	let a = BigUint::new_witness(&builder, 32);
	let b = BigUint::new_witness(&builder, 32);

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
	verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
}

proptest! {
	#[test]
	fn prop_add_multi_limb(vals in prop::collection::vec((any::<u64>(), any::<u64>()), 0..=16)) {
		// Test multi-limb addition with carry propagation

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
		prop_assume!(carry == 0);

		let builder = CircuitBuilder::new();
		let num_limbs = vals.len();

		let a = BigUint::new_witness(&builder, num_limbs);
		let b = BigUint::new_witness(&builder, num_limbs);

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
			assert_eq!(
				w[result.limbs[i]], Word(expected[i]),
				"Result Limb {} mismatch: got {}, expected {}",
				i, w[result.limbs[i]].0, expected[i]
			);
		}

		verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_mul_with_values(
		a_limbs in prop::collection::vec(any::<u64>(), 1..10),
		b_limbs in prop::collection::vec(any::<u64>(), 1..10)
	) {
		let builder = CircuitBuilder::new();

		let a = BigUint::new_inout(&builder, a_limbs.len());
		let b = BigUint::new_inout(&builder, b_limbs.len());

		let result = mul(&builder, &a, &b);

		let cs = builder.build();
		let mut w = cs.new_witness_filler();

		for (i, &val) in a_limbs.iter().enumerate() {
			w[a.limbs[i]] = Word(val);
		}
		for (i, &val) in b_limbs.iter().enumerate() {
			w[b.limbs[i]] = Word(val);
		}

		let a_big = from_u64_limbs(&a_limbs);
		let b_big = from_u64_limbs(&b_limbs);
		let expected = &a_big * &b_big;

		cs.populate_wire_witness(&mut w).unwrap();

		let result_big = biguint_to_num_biguint(&w, &result);

		assert_eq!(
			result_big, expected,
			"Multiplication failed: {a_big} * {b_big} = {result_big} (expected {expected})"
		);

		verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_square_with_values(a_limbs in prop::collection::vec(any::<u64>(), 1..10)) {
		let builder = CircuitBuilder::new();

		let a = BigUint::new_witness(&builder, a_limbs.len());
		let result = square(&builder, &a);

		let cs = builder.build();

		let mut w = cs.new_witness_filler();
		for (i, &val) in a_limbs.iter().enumerate() {
			w[a.limbs[i]] = Word(val);
		}

		let a_big = from_u64_limbs(&a_limbs);
		let expected = &a_big * &a_big;

		cs.populate_wire_witness(&mut w).unwrap();

		let result_big = biguint_to_num_biguint(&w, &result);

		assert_eq!(
			result_big, expected,
			"Squaring failed: {a_big}^2 = {result_big} (expected {expected})"
		);

		verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn prop_square_vs_mul_equivalence(vals in prop::collection::vec(any::<u64>(), 1..=8)) {
		let builder = CircuitBuilder::new();

		let a = BigUint::new_witness(&builder, vals.len());

		let square_result = square(&builder, &a);
		let mul_result = mul(&builder, &a, &a);

		let cs = builder.build();
		let mut w = cs.new_witness_filler();

		for (i, &val) in vals.iter().enumerate() {
			w[a.limbs[i]] = Word(val);
		}

		cs.populate_wire_witness(&mut w).unwrap();

		let square_big = biguint_to_num_biguint(&w, &square_result);
		let mul_big = biguint_to_num_biguint(&w, &mul_result);

		assert_eq!(square_big, mul_big, "square(a) != mul(a,a): {square_big} != {mul_big}");

		verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn prop_assert_eq_equal(vals in prop::collection::vec(any::<u64>(), 0..=8)) {
		let builder = CircuitBuilder::new();
		let a = BigUint::new_witness(&builder, vals.len());
		let b = BigUint::new_witness(&builder, vals.len());

		assert_eq(&builder, "prop_assert_eq", &a, &b);

		let cs = builder.build();
		let mut w = cs.new_witness_filler();

		// Set same values for both inputs
		for (i, &val) in vals.iter().enumerate() {
			w[a.limbs[i]] = Word(val);
			w[b.limbs[i]] = Word(val);
		}

		cs.populate_wire_witness(&mut w).unwrap();
		verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn prop_assert_eq_different(vals in prop::collection::vec((any::<u64>(), any::<u64>()), 1..=8)) {
		let a_vals: Vec<u64> = vals.iter().map(|(a, _)| *a).collect();
		let b_vals: Vec<u64> = vals.iter().map(|(_, b)| *b).collect();
		// Skip if they're actually equal
		prop_assume!(a_vals != b_vals);

		let builder = CircuitBuilder::new();
		let a = BigUint::new_witness(&builder, a_vals.len());
		let b = BigUint::new_witness(&builder, b_vals.len());

		assert_eq(&builder, "prop_assert_eq_different", &a, &b);

		let cs = builder.build();
		let mut w = cs.new_witness_filler();

		for (i, &val) in a_vals.iter().enumerate() {
			w[a.limbs[i]] = Word(val);
		}
		for (i, &val) in b_vals.iter().enumerate() {
			w[b.limbs[i]] = Word(val);
		}

		assert!(cs.populate_wire_witness(&mut w).is_err());
	}

	#[test]
	fn prop_mod_reduce(
		a_vals in prop::collection::vec(any::<u64>(), 1..=10),
		mod_vals in prop::collection::vec(any::<u64>(), 1..=10)
	) {
		prop_assume!(mod_vals.len() <= a_vals.len());
		prop_assume!(!mod_vals.iter().all(|&v| v == 0));

		let builder = CircuitBuilder::new();
		let a = BigUint::new_witness(&builder, a_vals.len());
		let modulus = BigUint::new_witness(&builder, mod_vals.len());

		let quotient = BigUint::new_witness(&builder, a.limbs.len());
		let remainder = BigUint::new_witness(&builder, modulus.limbs.len());

		let circuit = ModReduce::new(&builder, a, modulus, quotient, remainder);

		let cs = builder.build();
		let mut w = cs.new_witness_filler();

		circuit.a.populate_limbs(&mut w, &a_vals);
		circuit.modulus.populate_limbs(&mut w, &mod_vals);

		let a_big = from_u64_limbs(&a_vals);
		let modulus_big = from_u64_limbs(&mod_vals);
		let (q_big, r_big) = a_big.div_rem(&modulus_big);

		let mut q_limbs = q_big.to_u64_digits();
		q_limbs.resize(circuit.quotient.limbs.len(), 0u64);
		circuit.quotient.populate_limbs(&mut w, &q_limbs);

		let mut r_limbs = r_big.to_u64_digits();
		r_limbs.resize(circuit.remainder.limbs.len(), 0u64);

		circuit.remainder.populate_limbs(&mut w, &r_limbs);

		cs.populate_wire_witness(&mut w).unwrap();

		let a_big = biguint_to_num_biguint(&w, &circuit.a);
		let modulus_big = biguint_to_num_biguint(&w, &circuit.modulus);
		let quotient_big = biguint_to_num_biguint(&w, &circuit.quotient);
		let remainder_big = biguint_to_num_biguint(&w, &circuit.remainder);

		let reconstructed = &quotient_big * &modulus_big + &remainder_big;
		assert_eq!(
			reconstructed, a_big,
			"ModReduce failed: {a_big} != {quotient_big} * {modulus_big} + {remainder_big}"
		);

		verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
	}

	#[test]
	fn prop_mod_reduce_invalid_inputs(
		a_vals in prop::collection::vec(any::<u64>(), 1..=10),
		mod_vals in prop::collection::vec(any::<u64>(), 1..=10),
		mut quotient_vals in prop::collection::vec(any::<u64>(), 0..=10),
		mut remainder_vals in prop::collection::vec(any::<u64>(), 0..=10)
	) {
		prop_assume!(mod_vals.len() <= a_vals.len());
		prop_assume!(!mod_vals.iter().all(|&v| v == 0));

		quotient_vals.resize(a_vals.len(), 0);
		remainder_vals.resize(mod_vals.len(), 0);

		let a_big = from_u64_limbs(&a_vals);
		let modulus_big = from_u64_limbs(&mod_vals);
		let (correct_q, correct_r) = a_big.div_rem(&modulus_big);
		let provided_q = from_u64_limbs(&quotient_vals);
		let provided_r = from_u64_limbs(&remainder_vals);

		// If the provided values are actually correct, skip this test case
		prop_assume!(provided_q != correct_q || provided_r != correct_r);

		let builder = CircuitBuilder::new();

		let a = BigUint::new_witness(&builder, a_vals.len());
		let modulus = BigUint::new_witness(&builder, mod_vals.len());
		let quotient = BigUint::new_witness(&builder, a_vals.len());
		let remainder = BigUint::new_witness(&builder, mod_vals.len());

		let circuit = ModReduce::new(&builder, a, modulus, quotient, remainder);

		let cs = builder.build();
		let mut w = cs.new_witness_filler();

		circuit.a.populate_limbs(&mut w, &a_vals);
		circuit.modulus.populate_limbs(&mut w, &mod_vals);
		circuit.quotient.populate_limbs(&mut w, &quotient_vals);
		circuit.remainder.populate_limbs(&mut w, &remainder_vals);

		// The circuit should fail to populate witnesses with incorrect values
		assert!(
			cs.populate_wire_witness(&mut w).is_err(),
			"Circuit incorrectly accepted invalid quotient/remainder: a={a_big}, mod={modulus_big}, q={provided_q} (correct={correct_q}), r={provided_r} (correct={correct_r})"
		);
	}
}
