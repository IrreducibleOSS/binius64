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
use crate::{
	compiler::{
		circuit,
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	constraint_system::{AndConstraint, ConstraintSystem},
	word::Word,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
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
		constants,
		inputs,
		outputs,
		..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

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
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	w[*z] = w[*x] ^ w[*y];
}
