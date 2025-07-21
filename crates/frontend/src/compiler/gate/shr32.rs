/// 32-bit logical right shift.
///
/// Returns `z = (x >> n) & MASK_32`.
///
/// # Algorithm
///
/// Shifts the input right by `n` bits and masks to 32 bits.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x >> n) ∧ MASK_32 = z`
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
	let [x, mask32] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };
	let [n] = data.immediates.as_slice() else {
		unreachable!()
	};

	let x_idx = circuit.witness_index(*x);
	let z_idx = circuit.witness_index(*z);
	let mask32_idx = circuit.witness_index(*mask32);

	// Constraint: Shift right with masking
	// (x >> n) ∧ MASK_32 = z
	cs.add_and_constraint(AndConstraint::abc(
		[ShiftedValueIndex::srl(x_idx, *n as usize)],
		[ShiftedValueIndex::plain(mask32_idx)],
		[ShiftedValueIndex::plain(z_idx)],
	));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [x, _mask32] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };
	let [n] = data.immediates.as_slice() else {
		unreachable!()
	};

	let result = w[*x].shr_32(*n);
	w[*z] = result;
}
