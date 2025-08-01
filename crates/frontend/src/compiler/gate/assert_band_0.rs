//! Assert that bitwise AND equals zero.
//!
//! Enforces `x & constant = 0`.
//!
//! # Algorithm
//!
//! Directly constrains that the bitwise AND of `x` with a constant equals zero.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `x ∧ constant = 0`

use binius_core::word::Word;

use crate::compiler::{
	circuit,
	constraint_builder::{ConstraintBuilder, empty},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam},
	pathspec::PathSpec,
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

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };

	// Constraint: x ∧ y = 0
	builder.and().a(*x).b(*y).c(empty()).build();
}

pub fn evaluate(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	w: &mut circuit::WitnessFiller,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };

	if (w[*x] & w[*y]) != Word::ZERO {
		w.flag_assertion_failed(assertion_path, |w| format!("{:?} & {:?} != 0", w[*x], w[*y]));
	}
}
