//! Equality assertion.
//!
//! Enforces `x = y` using a ZERO constraint.
//!
//! # Algorithm
//!
//! Uses the property that `x = y` iff `x ^ y = 0`.
//! This is enforced as `x ⊕ y = 0`.
//!
//! # Constraints
//!
//! The gate generates 1 ZERO constraint:
//! - `x ⊕ y = 0`

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, xor2},
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
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };

	// Constraint: x ⊕ y = 0
	builder.zero().xor(xor2(*x, *y)).build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam { inputs, .. } = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	builder.emit_assert_eq(wire_to_reg(*x), wire_to_reg(*y), assertion_path.as_u32());
}
