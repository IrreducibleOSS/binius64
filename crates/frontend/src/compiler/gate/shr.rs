/// Logical right shift.
///
/// Returns `z = x >> n`.
///
/// # Algorithm
///
/// Performs a logical right shift by `n` bits. The constraint system allows
/// referencing shifted versions of values directly without additional gates.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x >> n) ∧ all-1 = z`
use super::{Gate, GateData};
use crate::{
	compiler::{Circuit, WitnessFiller},
	constraint_system::{AndConstraint, ConstraintSystem, ShiftedValueIndex},
};

pub fn constrain(_gate: Gate, data: &GateData, circuit: &Circuit, cs: &mut ConstraintSystem) {
	let [x, all_1] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };
	let [n] = data.immediates.as_slice() else {
		unreachable!()
	};

	let x_idx = circuit.witness_index(*x);
	let z_idx = circuit.witness_index(*z);
	let all_1_idx = circuit.witness_index(*all_1);

	// Constraint: Logical right shift
	// (x >> n) ∧ all-1 = z
	cs.add_and_constraint(AndConstraint::abc(
		[ShiftedValueIndex::srl(x_idx, *n as usize)],
		[ShiftedValueIndex::plain(all_1_idx)],
		[ShiftedValueIndex::plain(z_idx)],
	));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut WitnessFiller) {
	let [x, _all_1] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };
	let [n] = data.immediates.as_slice() else {
		unreachable!()
	};

	let result = w[*x] >> *n;
	w[*z] = result;
}
