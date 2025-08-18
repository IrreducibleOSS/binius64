//! N-way bitwise XOR operation.
//!
//! Returns `z = x0 ^ x1 ^ ... ^ xn`.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `(x0 ⊕ x1 ⊕ ... ⊕ xn) ∧ all-1 = z`

use binius_core::word::Word;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, WireExprTerm, xor_multi},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

pub fn shape(dimensions: &[usize]) -> OpcodeShape {
	let [n_inputs] = dimensions else {
		unreachable!()
	};
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: *n_inputs,
		n_out: 1,
		n_internal: 0,
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		constants,
		inputs,
		outputs,
		..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	// Constraint: N-way Bitwise XOR
	//
	// (x0 ⊕ x1 ⊕ ... ⊕ xn) ∧ all-1 = z
	let terms: Vec<WireExprTerm> = inputs.iter().map(|&w| w.into()).collect();
	builder.and().a(xor_multi(terms)).b(*all_1).c(*z).build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [z] = outputs else { unreachable!() };

	let input_regs: Vec<u32> = inputs.iter().map(|&wire| wire_to_reg(wire)).collect();
	builder.emit_bxor_multi(wire_to_reg(*z), &input_regs);
}
