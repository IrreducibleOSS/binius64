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

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, empty},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
	pathspec::PathSpec,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 2,
		n_out: 0,
		n_aux: 0,
		// 1 scratch for the intermediate computation of the AND.
		n_scratch: 1,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };

	// Constraint: x ∧ y = 0
	builder.and().a(*x).b(*y).c(empty()).build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam {
		inputs, scratch, ..
	} = data.gate_param();
	let [x, c] = inputs else { unreachable!() };
	let [and_result] = scratch else {
		unreachable!()
	};

	// Compute x & c into scratch register
	builder.emit_band(wire_to_reg(*and_result), wire_to_reg(*x), wire_to_reg(*c));

	// Assert the result is zero
	builder.emit_assert_zero(wire_to_reg(*and_result), assertion_path.as_u32());
}
