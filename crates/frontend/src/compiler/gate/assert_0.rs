/// Assert that a wire equals zero.
///
/// Enforces `x = 0` using an AND constraint.
///
/// # Algorithm
///
/// Uses the constraint `x ∧ all-1 = 0`, which forces `x = 0`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ all-1 = 0`
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
		n_in: 1,
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
	let GateParam {
		constants, inputs, ..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [x] = inputs else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let all_1_idx = circuit.witness_index(*all_1);

	// Constraint: x ∧ all-1 = 0
	cs.add_and_constraint(AndConstraint::plain_abc([x_idx], [all_1_idx], []));
}

pub fn evaluate(
	_gate: Gate,
	data: &GateData,
	assertion_name: Option<&String>,
	w: &mut circuit::WitnessFiller,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x] = inputs else { unreachable!() };

	if w[*x] != Word::ZERO {
		let name = assertion_name
			.map(|s| s.as_str())
			.unwrap_or("<unnamed assertion>");
		w.flag_assertion_failed(|w| format!("{} failed: {:?} != 0", name, w[*x]));
	}
}
