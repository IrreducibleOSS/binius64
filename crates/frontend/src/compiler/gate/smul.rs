//! Smul gate implements 64-bit × 64-bit → 128-bit signed multiplication.
//!
//! Algorithm is unsigned multiplication with high-word correction
//! from: Hennessy & Patterson, "Computer Architecture: A Quantitative Approach"
//! 6th Edition (2019), Appendix J.2, pp. J-11 to J-13
//!
//! For signed two's complement multiplication a × b:
//! 1. Perform unsigned multiplication of bit patterns
//! 2. If a < 0, subtract b from high word (corrects for 2^64 × b error)
//! 3. If b < 0, subtract a from high word (corrects for 2^64 × a error)
//!
//! Notation
//!
//! Bit Patterns & Interpretations:
//! - w ∈ {0,1}^64 - a 64-bit pattern (word)
//! - \[w\]_u ∈ \[0, 2^64-1\] - interpret w as unsigned integer
//! - \[w\]_s ∈ \[-2^63, 2^63-1\] - interpret w as signed integer (two's complement)
//! - w\[i\] - bit i of word w (0-indexed, w\[63\] is MSB)
//!
//! Operations:
//! - ×_Z - integer multiplication in Z
//! - +_Z - integer addition in Z
//! - (·) mod 2^64 - reduction to 64 bits
//! - Low-cost operations (FREE in constraint operands):
//!   - ⊕ - XOR (bitwise, also field addition in GF(2))
//!   - ∧ - AND (bitwise)
//!   - >>_a - arithmetic right shift (sign-extending)
//!   - >>_l - logical right shift
//!   - << - logical left shift
//!   - Any shift amount (0-63 bits) of any wire
//!
//! Available Constraint Primitives:
//! - MUL(a,b,hi,lo): Verifies [a]_u ×_Z [b]_u = [hi]_u · 2^64 + [lo]_u
//! - AND(A,B,C): Verifies A ∧ B = C where A,B,C are XOR-sums of shifted words
//!
//! Goal Constraint
//!
//! Given: a, b ∈ {0,1}^64 (inputs as bit patterns)
//! Want: hi_s, lo_s ∈ {0,1}^64 such that [a]_s ×_Z [b]_s = [hi_s]_s · 2^64 + [lo_s]_u
//!
//! Derivation
//!
//! Step 1: Relationship between signed and unsigned interpretations
//!
//! For any w ∈ {0,1}^64:
//! [w]_s = [w]_u - 2^64 · w[63]
//!
//! Step 2: Signed multiplication in terms of unsigned
//!
//! [a]_s ×_Z [b]_s = ([a]_u - 2^64 · a[63]) ×_Z ([b]_u - 2^64 · b[63])
//!                  = [a]_u ×_Z [b]_u - [a]_u · 2^64 · b[63] - [b]_u · 2^64 · a[63] + 2^128 · a[63]
//! · b[63]
//!
//! Since we only care about the 128-bit result, the 2^128 term vanishes:
//! [a]_s ×_Z [b]_s mod 2^128 = [a]_u ×_Z [b]_u - [a]_u · 2^64 · b[63] - [b]_u · 2^64 · a[63]
//!
//! Step 3: Effect on high/low words
//!
//! Let [a]_u ×_Z [b]_u = hi_u · 2^64 + lo_u where hi_u, lo_u ∈ [0, 2^64-1]
//!
//! Then:
//! [a]_s ×_Z [b]_s = (hi_u · 2^64 + lo_u) - [a]_u · 2^64 · b[63] - [b]_u · 2^64 · a[63]
//!                 = (hi_u - [a]_u · b[63] - [b]_u · a[63]) · 2^64 + lo_u
//!
//! So: lo_s = lo_u (low word unchanged)
//! And: [hi_s]_u = (hi_u - [a]_u · b[63] - [b]_u · a[63]) mod 2^64
//!
//! Step 4: Rewrite for constraint verification
//!
//! Since we can't constrain subtraction directly, we rewrite:
//! hi_u = ([hi_s]_u + [a]_u · b[63] + [b]_u · a[63]) mod 2^64
//!
//! Let:
//! - correction_a = a[63] ? [b]_u : 0 (implemented as (a >>_a 63) ∧ b)
//! - correction_b = b[63] ? [a]_u : 0 (implemented as (b >>_a 63) ∧ a)
//!
//! Then we need to verify:
//! hi_u = ([hi_s]_u +_Z correction_a +_Z correction_b) mod 2^64
//!
//! Step 5: Constraining modular addition
//!
//! To verify z = (x +_Z y) mod 2^64 using AND constraints, we use carry propagation:
//!
//! Let carry ∈ {0,1}^64 be the carry bits where:
//! - carry[0] = x[0] ∧ y[0]
//! - carry[i] = (x[i] ∧ y[i]) ∨ ((x[i] ⊕ y[i]) ∧ carry[i-1])
//!
//! This is equivalent to the AND constraint:
//! (x ⊕ (carry << 1)) ∧ (y ⊕ (carry << 1)) = carry ⊕ (carry << 1)
//!
//! And the sum is:
//! z = x ⊕ y ⊕ (carry << 1)
//!
//! Complete Constraint System
//!
//! Given inputs a, b and outputs hi_s, lo_s, we constrain:
//!
//! 1. MUL: [a]_u ×_Z [b]_u = hi_u · 2^64 + lo_u
//! 2. AND: (a >>_a 63) ∧ b = correction_a
//! 3. AND: (b >>_a 63) ∧ a = correction_b
//! 4. AND (carry propagation 1): (hi_s ⊕ (carry_a << 1)) ∧ (correction_a ⊕ (carry_a << 1)) =
//!    carry_a ⊕ (carry_a << 1)
//! 5. AND: hi_s ⊕ correction_a ⊕ (carry_a << 1) = result1
//! 6. AND (carry propagation 2): (result1 ⊕ (carry_b << 1)) ∧ (correction_b ⊕ (carry_b << 1)) =
//!    carry_b ⊕ (carry_b << 1)
//! 7. AND: result1 ⊕ correction_b ⊕ (carry_b << 1) = hi_u
//! 8. AND: lo_u = lo_s
//!
//! Total: 7 x AND, 1 x MUL

use crate::compiler::{
	constraint_builder::ConstraintBuilder,
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 2,
		n_out: 2,
		n_internal: 7, // hi_u, lo_u, correction_a, correction_b, carry_a, result1, carry_b
		n_scratch: 1,  // Need 1 scratch register for the final sum we don't need
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	use crate::compiler::constraint_builder::{sar, sll, xor2, xor3};

	let GateParam {
		inputs,
		outputs,
		internal,
		..
	} = data.gate_param();
	let [a, b] = inputs else { unreachable!() };
	let [hi, lo] = outputs else { unreachable!() };
	let [
		hi_u,
		lo_u,
		correction_a,
		correction_b,
		carry_a,
		result1,
		carry_b,
	] = internal
	else {
		unreachable!()
	};

	// Step 1: Verify unsigned multiplication
	// a * b = (hi_u << 64) | lo_u
	builder.mul().a(*a).b(*b).hi(*hi_u).lo(*lo_u).build();

	// Step 2: Compute corrections based on sign bits
	// correction_a = (a >> 63) & b  (if a < 0, subtract b from high word)
	// correction_b = (b >> 63) & a  (if b < 0, subtract a from high word)
	builder.and().a(sar(*a, 63)).b(*b).c(*correction_a).build();

	builder.and().a(sar(*b, 63)).b(*a).c(*correction_b).build();

	// Step 3: Verify hi_u = hi + correction_a + correction_b
	// These are 64-bit modular additions, so we use carry propagation to verify
	// the arithmetic is performed correctly.
	// Using carry propagation for first addition: hi + correction_a
	let carry_a_sll_1 = sll(*carry_a, 1);

	// Carry propagation for: result1 = hi + correction_a
	// (hi ⊕ (carry_a << 1)) ∧ (correction_a ⊕ (carry_a << 1)) = carry_a ⊕ (carry_a << 1)
	builder
		.and()
		.a(xor2(*hi, carry_a_sll_1))
		.b(xor2(*correction_a, carry_a_sll_1))
		.c(xor2(*carry_a, carry_a_sll_1))
		.build();

	// Verify intermediate result: result1 = hi ⊕ correction_a ⊕ (carry_a << 1)
	builder
		.and()
		.a(xor3(*hi, *correction_a, carry_a_sll_1))
		.b(*result1)
		.c(*result1)
		.build();

	// Now verify second addition: hi_u = result1 + correction_b
	let carry_b_sll_1 = sll(*carry_b, 1);

	// Carry propagation for: hi_u = result1 + correction_b
	builder
		.and()
		.a(xor2(*result1, carry_b_sll_1))
		.b(xor2(*correction_b, carry_b_sll_1))
		.c(xor2(*carry_b, carry_b_sll_1))
		.build();

	// Final verification: hi_u = result1 ⊕ correction_b ⊕ (carry_b << 1)
	builder
		.and()
		.a(xor3(*result1, *correction_b, carry_b_sll_1))
		.b(*hi_u)
		.c(*hi_u)
		.build();

	// Step 4: Low word is the same for signed and unsigned
	builder.and().a(*lo_u).b(*lo).c(*lo).build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(crate::compiler::gate_graph::Wire) -> u32,
) {
	let GateParam {
		inputs,
		outputs,
		internal,
		scratch,
		..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [hi, lo] = outputs else { unreachable!() };
	let [
		hi_u,
		lo_u,
		correction_a,
		correction_b,
		carry_a,
		result1,
		carry_b,
	] = internal
	else {
		unreachable!()
	};
	let [scratch_sum] = scratch else {
		unreachable!()
	};

	// Compute signed multiplication result for outputs
	builder.emit_smul(wire_to_reg(*hi), wire_to_reg(*lo), wire_to_reg(*x), wire_to_reg(*y));

	// Compute unsigned multiplication for internal wires
	builder.emit_imul(wire_to_reg(*hi_u), wire_to_reg(*lo_u), wire_to_reg(*x), wire_to_reg(*y));

	// Compute correction_a = (x >> 63) & y
	// First get sign bit mask of x
	builder.emit_sar(wire_to_reg(*correction_a), wire_to_reg(*x), 63);
	// Then AND with y to get correction
	builder.emit_band(wire_to_reg(*correction_a), wire_to_reg(*correction_a), wire_to_reg(*y));

	// Compute correction_b = (y >> 63) & x
	// First get sign bit mask of y
	builder.emit_sar(wire_to_reg(*correction_b), wire_to_reg(*y), 63);
	// Then AND with x to get correction
	builder.emit_band(wire_to_reg(*correction_b), wire_to_reg(*correction_b), wire_to_reg(*x));

	// Compute carry_a and result1 for: result1 = hi + correction_a
	// iadd_cout computes both sum and carry
	builder.emit_iadd_cout(
		wire_to_reg(*result1),
		wire_to_reg(*carry_a),
		wire_to_reg(*hi),
		wire_to_reg(*correction_a),
	);

	// Compute carry_b for: hi_u = result1 + correction_b
	// We don't need the final sum (it should be hi_u which we already have)
	// But we need carry_b for constraint verification
	// Use the scratch register for the sum we don't need
	builder.emit_iadd_cout(
		wire_to_reg(*scratch_sum),
		wire_to_reg(*carry_b),
		wire_to_reg(*result1),
		wire_to_reg(*correction_b),
	);
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;
	use proptest::prelude::*;

	use crate::{compiler::CircuitBuilder, constraint_verifier::verify_constraints};

	// Property: SMUL gate should correctly compute signed multiplication
	proptest! {
		#[test]
		fn test_smul_correctness(x_val: i64, y_val: i64) {
			// Build a circuit with SMUL gate
			let builder = CircuitBuilder::new();
			let x = builder.add_inout();
			let y = builder.add_inout();
			let (hi, lo) = builder.smul(x, y);
			let expected_hi = builder.add_inout();
			let expected_lo = builder.add_inout();
			builder.assert_eq("smul_hi", hi, expected_hi);
			builder.assert_eq("smul_lo", lo, expected_lo);
			let circuit = builder.build();

			let mut w = circuit.new_witness_filler();
			w[x] = Word(x_val as u64);
			w[y] = Word(y_val as u64);

			// Compute expected result using native 128-bit signed multiplication
			let result = (x_val as i128) * (y_val as i128);
			let expected_hi_val = (result >> 64) as u64;
			let expected_lo_val = result as u64;

			w[expected_hi] = Word(expected_hi_val);
			w[expected_lo] = Word(expected_lo_val);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	// Property: SMUL should be commutative
	proptest! {
		#[test]
		fn test_smul_commutative(x_val: i64, y_val: i64) {
			// Build a circuit that tests commutativity
			let builder = CircuitBuilder::new();
			let x = builder.add_inout();
			let y = builder.add_inout();

			// Compute x * y
			let (hi1, lo1) = builder.smul(x, y);
			// Compute y * x
			let (hi2, lo2) = builder.smul(y, x);

			// Assert they are equal
			builder.assert_eq("hi_equal", hi1, hi2);
			builder.assert_eq("lo_equal", lo1, lo2);
			let circuit = builder.build();

			let mut w = circuit.new_witness_filler();
			w[x] = Word(x_val as u64);
			w[y] = Word(y_val as u64);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	// Property: SMUL with 0 should give 0
	proptest! {
		#[test]
		fn test_smul_zero_identity(x_val: i64) {
			// Build a circuit with SMUL gate
			let builder = CircuitBuilder::new();
			let x = builder.add_inout();
			let zero = builder.add_constant_64(0);
			let (hi, lo) = builder.smul(x, zero);

			// Result should be 0
			builder.assert_0("hi_is_zero", hi);
			builder.assert_0("lo_is_zero", lo);
			let circuit = builder.build();

			let mut w = circuit.new_witness_filler();
			w[x] = Word(x_val as u64);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	// Property: SMUL with 1 should give the original value
	proptest! {
		#[test]
		fn test_smul_one_identity(x_val: i64) {
			// Build a circuit with SMUL gate
			let builder = CircuitBuilder::new();
			let x = builder.add_inout();
			let one = builder.add_constant_64(1);
			let (hi, lo) = builder.smul(x, one);

			// Low word should equal x, high word should be sign extension
			builder.assert_eq("lo_equals_x", lo, x);

			// High word should be all 0s or all 1s depending on sign of x
			let expected_hi = if x_val < 0 {
				builder.add_constant(Word::ALL_ONE)
			} else {
				builder.add_constant_64(0)
			};
			builder.assert_eq("hi_sign_extended", hi, expected_hi);
			let circuit = builder.build();

			let mut w = circuit.new_witness_filler();
			w[x] = Word(x_val as u64);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	// Property: SMUL with -1 should give the negation
	proptest! {
		#[test]
		fn test_smul_neg_one(x_val: i64) {
			// Build a circuit with SMUL gate
			let builder = CircuitBuilder::new();
			let x = builder.add_inout();
			let neg_one = builder.add_constant(Word::ALL_ONE); // -1 in two's complement
			let (hi, lo) = builder.smul(x, neg_one);
			let expected_hi = builder.add_inout();
			let expected_lo = builder.add_inout();
			builder.assert_eq("smul_hi", hi, expected_hi);
			builder.assert_eq("smul_lo", lo, expected_lo);
			let circuit = builder.build();

			let mut w = circuit.new_witness_filler();
			w[x] = Word(x_val as u64);

			// Expected result is -x
			let result = -(x_val as i128);
			let expected_hi_val = (result >> 64) as u64;
			let expected_lo_val = result as u64;

			w[expected_hi] = Word(expected_hi_val);
			w[expected_lo] = Word(expected_lo_val);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}

	// Test that constraints actually verify correctly
	#[test]
	fn test_smul_constraint_verification() {
		// Build a circuit with SMUL gate
		let builder = CircuitBuilder::new();
		let x = builder.add_inout();
		let y = builder.add_inout();
		let (hi, lo) = builder.smul(x, y);
		let expected_hi = builder.add_inout();
		let expected_lo = builder.add_inout();
		builder.assert_eq("smul_hi", hi, expected_hi);
		builder.assert_eq("smul_lo", lo, expected_lo);
		let circuit = builder.build();

		// Test with negative × negative = positive
		let mut w = circuit.new_witness_filler();
		w[x] = Word(-5i64 as u64);
		w[y] = Word(-7i64 as u64);

		// -5 × -7 = 35 = 0x0000000000000023
		w[expected_hi] = Word(0);
		w[expected_lo] = Word(35);
		w.circuit.populate_wire_witness(&mut w).unwrap();

		// Constraints should verify correctly
		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	// Test specific edge cases that are important for signed multiplication
	#[test]
	fn test_smul_edge_cases() {
		let builder = CircuitBuilder::new();
		let x = builder.add_inout();
		let y = builder.add_inout();
		let (hi, lo) = builder.smul(x, y);
		let expected_hi = builder.add_inout();
		let expected_lo = builder.add_inout();
		builder.assert_eq("smul_hi", hi, expected_hi);
		builder.assert_eq("smul_lo", lo, expected_lo);
		let circuit = builder.build();

		// Important edge cases for signed multiplication
		let test_cases = [
			// MIN × MIN (overflow case)
			(i64::MIN, i64::MIN),
			// MIN × MAX
			(i64::MIN, i64::MAX),
			// MAX × MAX
			(i64::MAX, i64::MAX),
			// MIN × -1 (special overflow)
			(i64::MIN, -1),
			// Powers of 2
			(1i64 << 31, 1i64 << 31),
			(-(1i64 << 31), 1i64 << 31),
			// Near overflow
			(1i64 << 32, 1i64 << 31),
			(-(1i64 << 32), 1i64 << 31),
		];

		for (x_val, y_val) in test_cases {
			let mut w = circuit.new_witness_filler();
			w[x] = Word(x_val as u64);
			w[y] = Word(y_val as u64);

			// Compute expected result using native 128-bit signed multiplication
			let result = (x_val as i128) * (y_val as i128);
			let expected_hi_val = (result >> 64) as u64;
			let expected_lo_val = result as u64;

			w[expected_hi] = Word(expected_hi_val);
			w[expected_lo] = Word(expected_lo_val);
			w.circuit.populate_wire_witness(&mut w).unwrap();

			// Verify constraints
			let cs = circuit.constraint_system();
			verify_constraints(cs, &w.into_value_vec()).unwrap();
		}
	}
}
