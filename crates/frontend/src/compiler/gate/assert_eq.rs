/// Equality assertion.
///
/// Enforces `x = y` using an AND constraint.
///
/// # Algorithm
///
/// Uses the property that `x = y` iff `x ^ y = 0`.
/// This is enforced as `(x ⊕ y) ∧ all-1 = 0`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x ⊕ y) ∧ all-1 = 0`
use super::{Gate, GateData};
use crate::{
	compiler::{Circuit, WitnessFiller},
	constraint_system::{AndConstraint, ConstraintSystem},
};

pub fn constrain(_gate: Gate, data: &GateData, circuit: &Circuit, cs: &mut ConstraintSystem) {
	let [x, y, all_1] = data.inputs() else {
		unreachable!()
	};

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let all_1_idx = circuit.witness_index(*all_1);

	// Constraint: (x ⊕ y) ∧ all-1 = 0
	cs.add_and_constraint(AndConstraint::plain_abc([x_idx, y_idx], [all_1_idx], []));
}

pub fn evaluate(
	_gate: Gate,
	data: &GateData,
	assertion_name: Option<&String>,
	w: &mut WitnessFiller,
) {
	let [x, y, _all_1] = data.inputs() else {
		unreachable!()
	};

	if w[*x] != w[*y] {
		let name = assertion_name
			.map(|s| s.as_str())
			.unwrap_or("<unnamed assertion>");
		w.flag_assertion_failed(format!("{} failed: {:?} != {:?}", name, w[*x], w[*y]));
	}
}
