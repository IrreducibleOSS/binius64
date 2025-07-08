//! Simple constraint verifier for testing

use crate::{
	constraint_system::{
		AndConstraint, ConstraintSystem, MulConstraint, ShiftVariant, ShiftedValueIndex, ValueVec,
	},
	word::Word,
};

/// Evaluates a shifted value from the witness
fn eval_shifted(witness: &ValueVec, sv: &ShiftedValueIndex) -> Word {
	let Word(val) = witness[sv.value_index];
	match sv.shift_variant {
		ShiftVariant::Sll => Word(val << sv.amount),
		ShiftVariant::Slr => Word(val >> sv.amount),
		ShiftVariant::Sar => Word(((val as i64) >> sv.amount) as u64),
	}
}

/// Evaluates an operand (XOR of shifted values)
fn eval_operand(witness: &ValueVec, operand: &[ShiftedValueIndex]) -> Word {
	operand
		.iter()
		.map(|sv| eval_shifted(witness, sv))
		.fold(Word(0), |acc, val| acc ^ val)
}

/// Verifies that an AND constraint is satisfied: (A & B) ^ C = 0
pub fn verify_and_constraint(witness: &ValueVec, constraint: &AndConstraint) -> Result<(), String> {
	let Word(a) = eval_operand(witness, &constraint.a);
	let Word(b) = eval_operand(witness, &constraint.b);
	let Word(c) = eval_operand(witness, &constraint.c);

	let result = (a & b) ^ c;
	if result != 0 {
		Err(format!(
			"AND constraint failed: ({a:016x} & {b:016x}) ^ {c:016x} = {result:016x} (expected 0)",
		))
	} else {
		Ok(())
	}
}

/// Verifies that a MUL constraint is satisfied: A * B = (HI << 64) | LO
pub fn verify_mul_constraint(witness: &ValueVec, constraint: &MulConstraint) -> Result<(), String> {
	let Word(a) = eval_operand(witness, &constraint.a);
	let Word(b) = eval_operand(witness, &constraint.b);
	let Word(lo) = eval_operand(witness, &constraint.lo);
	let Word(hi) = eval_operand(witness, &constraint.hi);

	let a_val = a as u128;
	let b_val = b as u128;
	let product = a_val * b_val;

	let expected_lo = (product & 0xFFFFFFFFFFFFFFFF) as u64;
	let expected_hi = (product >> 64) as u64;

	if lo != expected_lo || hi != expected_hi {
		Err(format!(
			"MUL constraint failed: {a:016x} * {b:016x} = {hi:016x}{lo:016x} (expected {expected_hi:016x}{expected_lo:016x})",
		))
	} else {
		Ok(())
	}
}

/// Verifies all constraints in a constraint system are satisfied by the witness
pub fn verify_constraints(cs: &ConstraintSystem, witness: &ValueVec) -> Result<(), String> {
	for (i, constraint) in cs.and_constraints.iter().enumerate() {
		verify_and_constraint(witness, constraint)
			.map_err(|e| format!("AND constraint {i} failed: {e}"))?;
	}
	for (i, constraint) in cs.mul_constraints.iter().enumerate() {
		verify_mul_constraint(witness, constraint)
			.map_err(|e| format!("MUL constraint {i} failed: {e}"))?;
	}
	Ok(())
}
