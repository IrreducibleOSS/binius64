/// 32-bit unsigned integer addition with carry propagation.
///
/// Returns `z = (x + y) & MASK_32` and `cout` containing carry bits.
///
/// # Algorithm
///
/// Performs 32-bit addition by computing the full 64-bit result and masking:
/// 1. Compute carry bits `cout` from `x + y` using carry propagation
/// 2. Extract the lower 32 bits: `z = (x ⊕ y ⊕ (cout << 1)) ∧ MASK_32`
///
/// # Constraints
///
/// The gate generates 2 AND constraints:
/// 1. Carry propagation: `(x ⊕ (cout << 1)) ∧ (y ⊕ (cout << 1)) = cout ⊕ (cout << 1)`
/// 2. Result masking: `(x ⊕ y ⊕ (cout << 1)) ∧ MASK_32 = z`
use super::{Gate, GateData};
use crate::{
	compiler::circuit,
	constraint_system::{AndConstraint, ConstraintSystem, ShiftedValueIndex},
};

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let [x, y, mask32] = data.inputs() else {
		unreachable!()
	};
	let [z, cout] = data.outputs() else {
		unreachable!()
	};

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let z_idx = circuit.witness_index(*z);
	let cout_idx = circuit.witness_index(*cout);
	let mask32_idx = circuit.witness_index(*mask32);

	// Constraint 1: Carry propagation
	//
	// (x ⊕ (cout << 1)) ∧ (y ⊕ (cout << 1)) = cout ⊕ (cout << 1)
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::plain(x_idx),
			ShiftedValueIndex::sll(cout_idx, 1),
		],
		[
			ShiftedValueIndex::plain(y_idx),
			ShiftedValueIndex::sll(cout_idx, 1),
		],
		[
			ShiftedValueIndex::plain(cout_idx),
			ShiftedValueIndex::sll(cout_idx, 1),
		],
	));
	// Constraint 2: Result masking
	//
	// (x ⊕ y ⊕ (cout << 1)) ∧ MASK_32 = z
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::plain(x_idx),
			ShiftedValueIndex::plain(y_idx),
			ShiftedValueIndex::sll(cout_idx, 1),
		],
		[ShiftedValueIndex::plain(mask32_idx)],
		[ShiftedValueIndex::plain(z_idx)],
	));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [x, y, _mask32] = data.inputs() else {
		unreachable!()
	};
	let [z, cout] = data.outputs() else {
		unreachable!()
	};

	let (sum, carry) = w[*x].iadd_cout_32(w[*y]);
	w[*z] = sum;
	w[*cout] = carry;
}
