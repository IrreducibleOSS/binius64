/// Bitwise AND operation.
///
/// Returns `z = x & y`.
///
/// # Algorithm
///
/// Computes the bitwise AND of two 64-bit words using a single AND constraint.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ y = z`
use crate::{
	compiler::{
		circuit,
		gate_graph::{Gate, GateData},
	},
	constraint_system::{AndConstraint, ConstraintSystem},
};

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let [x, y] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let z_idx = circuit.witness_index(*z);

	// Constraint: Bitwise AND
	//
	// x ∧ y = z
	cs.add_and_constraint(AndConstraint::plain_abc([x_idx], [y_idx], [z_idx]));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [x, y] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };

	w[*z] = w[*x] & w[*y];
}
