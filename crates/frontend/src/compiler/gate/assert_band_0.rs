/// Assert that bitwise AND equals zero.
///
/// Enforces `x & constant = 0`.
///
/// # Algorithm
///
/// Directly constrains that the bitwise AND of `x` with a constant equals zero.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ constant = 0`
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
		const_in: &[],
		n_in: 2,
		n_out: 0,
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
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);

	// Constraint: x ∧ y = 0
	cs.add_and_constraint(AndConstraint::plain_abc([x_idx], [y_idx], []));
}

pub fn evaluate(
	_gate: Gate,
	data: &GateData,
	assertion_name: Option<&String>,
	w: &mut circuit::WitnessFiller,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };

	if (w[*x] & w[*y]) != Word::ZERO {
		let name = assertion_name
			.map(|s| s.as_str())
			.unwrap_or("<unnamed assertion>");
		w.flag_assertion_failed(|w| format!("{} failed: {:?} & {:?} != 0", name, w[*x], w[*y]));
	}
}
