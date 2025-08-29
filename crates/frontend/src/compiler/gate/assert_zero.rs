//! Assert that a wire equals zero.
//!
//! Enforces `x = 0` using an AND constraint.
//!
//! # Algorithm
//!
//! Uses the constraint `x ∧ all-1 = 0`, which forces `x = 0`.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `x ∧ all-1 = 0`

use binius_core::word::Word;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, empty},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
	pathspec::PathSpec,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: 1,
		n_out: 0,
		n_aux: 0,
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		constants, inputs, ..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [x] = inputs else { unreachable!() };

	// Constraint: x ∧ all-1 = 0
	builder.and().a(*x).b(*all_1).c(empty()).build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x] = inputs else { unreachable!() };
	builder.emit_assert_zero(wire_to_reg(*x), assertion_path.as_u32());
}
