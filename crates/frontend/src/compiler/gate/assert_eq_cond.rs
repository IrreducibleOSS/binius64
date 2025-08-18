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

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, empty, xor2},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
	pathspec::PathSpec,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 3,
		n_out: 0,
		n_aux: 0,
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y, mask] = inputs else { unreachable!() };

	// Constraint: (x ⊕ y) ∧ mask = 0
	builder.and().a(xor2(*x, *y)).b(*mask).c(empty()).build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y, mask] = inputs else { unreachable!() };
	builder.emit_assert_cond(
		wire_to_reg(*mask),
		wire_to_reg(*x),
		wire_to_reg(*y),
		assertion_path.as_u32(),
	);
}
