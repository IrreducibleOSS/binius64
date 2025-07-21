/// Bitwise OR operation.
///
/// Returns `z = x | y`.
///
/// # Algorithm
///
/// Computes the bitwise OR using De Morgan's law: `x | y = ¬(¬x ∧ ¬y)`.
/// This is implemented as `x ∧ y = (x ⊕ y ⊕ z)`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ y = x ⊕ y ⊕ z`
use crate::{
	compiler::{
		circuit,
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	constraint_system::{AndConstraint, ConstraintSystem},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 2,
		n_out: 1,
		n_internal: 0,
		n_imm: 0,
	}
}

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let z_idx = circuit.witness_index(*z);

	// Constraint: Bitwise OR
	//
	// x ∧ y = x ⊕ y ⊕ z
	cs.add_and_constraint(AndConstraint::plain_abc([x_idx], [y_idx], [x_idx, y_idx, z_idx]));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	w[*z] = w[*x] | w[*y];
}
