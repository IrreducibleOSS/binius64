//! Assert that a wire equals zero.
//!
//! Enforces `x = 0` using an AND constraint.
//!
//! # Algorithm
//!
//! Uses the constraint `x = 0`.
//!
//! # Constraints
//!
//! The gate generates 1 ZERO constraint:
//! - `x = 0`

use crate::compiler::{
	constraint_builder::ConstraintBuilder,
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
	pathspec::PathSpec,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 1,
		n_out: 0,
		n_aux: 0,
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x] = inputs else { unreachable!() };

	// Constraint: x = 0
	builder.zero().xor(*x).build();
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
