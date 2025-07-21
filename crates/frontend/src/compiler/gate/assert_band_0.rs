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
use super::{Gate, GateData};
use crate::{
	compiler::circuit,
	constraint_system::{AndConstraint, ConstraintSystem},
	word::Word,
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
	let [x, y] = data.inputs() else {
		unreachable!()
	};

	if (w[*x] & w[*y]) != Word::ZERO {
		let name = assertion_name
			.map(|s| s.as_str())
			.unwrap_or("<unnamed assertion>");
		w.flag_assertion_failed(format!("{} failed: {:?} & {:?} != 0", name, w[*x], w[*y]));
	}
}
