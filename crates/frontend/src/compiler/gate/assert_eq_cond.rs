/// Conditional equality assertion.
///
/// Enforces `x = y` when `mask = all-1`, no constraint when `mask = 0`.
///
/// # Algorithm
///
/// Uses a mask to conditionally enforce equality: `(x ^ y) & mask = 0`.
/// When mask is all-1, this enforces `x = y`. When mask is 0, the constraint is satisfied
/// trivially.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x ⊕ y) ∧ mask = 0`
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
		n_in: 3,
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
	let [x, y, mask] = inputs else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let mask_idx = circuit.witness_index(*mask);

	// Constraint: (x ⊕ y) ∧ mask = 0
	cs.add_and_constraint(AndConstraint::plain_abc([x_idx, y_idx], [mask_idx], []));
}

pub fn evaluate(
	_gate: Gate,
	data: &GateData,
	assertion_name: Option<&String>,
	w: &mut circuit::WitnessFiller,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y, mask] = inputs else { unreachable!() };

	let diff = w[*x] ^ w[*y];
	if (diff & w[*mask]) != Word::ZERO {
		let name = assertion_name
			.map(|s| s.as_str())
			.unwrap_or("<unnamed assertion>");
		w.flag_assertion_failed(|w| {
			format!("{} failed: ({:?} ^ {:?}) & {:?} != 0", name, w[*x], w[*y], w[*mask])
		});
	}
}
