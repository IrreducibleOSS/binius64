/// Bitwise XOR operation.
///
/// Returns `z = x ^ y`.
///
/// # Algorithm
///
/// Computes the bitwise XOR using the identity: `x ^ y = ¬(x ∧ y)`.
/// This is implemented as `(x ⊕ y) ∧ all-1 = z`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x ⊕ y) ∧ all-1 = z`
use super::{Gate, GateData};
use crate::{
	compiler::circuit,
	constraint_system::{AndConstraint, ConstraintSystem},
};

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let [x, y, all_1] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let z_idx = circuit.witness_index(*z);
	let all_1_idx = circuit.witness_index(*all_1);

	// Constraint: Bitwise XOR
	//
	// (x ⊕ y) ∧ all-1 = z
	cs.add_and_constraint(AndConstraint::plain_abc([x_idx, y_idx], [all_1_idx], [z_idx]));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [x, y, _all_1] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };

	w[*z] = w[*x] ^ w[*y];
}
