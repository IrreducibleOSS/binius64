//! Equality assertion.
//!
//! Enforces `x = y` using an AND constraint.
//!
//! # Algorithm
//!
//! Uses the property that `x = y` iff `x ^ y = 0`.
//! This is enforced as `(x ⊕ y) ∧ all-1 = 0`.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `(x ⊕ y) ∧ all-1 = 0`
use binius_core::word::Word;

use crate::compiler::{
	circuit,
	constraint_builder::{ConstraintBuilder, empty, xor2},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam},
	pathspec::PathSpec,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: 2,
		n_out: 0,
		n_internal: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		constants, inputs, ..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [x, y] = inputs else { unreachable!() };

	// Constraint: (x ⊕ y) ∧ all-1 = 0
	builder.and().a(xor2(*x, *y)).b(*all_1).c(empty()).build();
}

pub fn evaluate(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	w: &mut circuit::WitnessFiller,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };

	if w[*x] != w[*y] {
		w.flag_assertion_failed(assertion_path, |w| format!("{:?} != {:?}", w[*x], w[*y]));
	}
}
