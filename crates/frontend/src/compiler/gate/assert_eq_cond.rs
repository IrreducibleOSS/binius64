//! Conditional equality assertion.
//!
//! Enforces `x = y` when `mask = all-1`, no constraint when `mask = 0`.
//!
//! # Algorithm
//!
//! Uses a mask to conditionally enforce equality: `(x ^ y) & mask = 0`.
//! When mask is all-1, this enforces `x = y`. When mask is 0, the constraint is satisfied
//! trivially.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `(x ⊕ y) ∧ mask = 0`

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
		const_in: &[],
		n_in: 3,
		n_out: 0,
		n_internal: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y, mask] = inputs else { unreachable!() };

	// Constraint: (x ⊕ y) ∧ mask = 0
	builder.and().a(xor2(*x, *y)).b(*mask).c(empty()).build();
}

pub fn evaluate(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	w: &mut circuit::WitnessFiller,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y, mask] = inputs else { unreachable!() };

	let diff = w[*x] ^ w[*y];
	if (diff & w[*mask]) != Word::ZERO {
		w.flag_assertion_failed(assertion_path, |w| {
			format!("({:?} ^ {:?}) & {:?} != 0", w[*x], w[*y], w[*mask])
		});
	}
}
