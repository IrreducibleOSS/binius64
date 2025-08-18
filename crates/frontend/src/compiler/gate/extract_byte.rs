//! Byte extraction from a 64-bit word.
//!
//! Returns `z = (word >> (8*j)) & 0xFF` where j=0 is the least significant byte.
//!
//! # Algorithm
//!
//! Extracts byte j from a 64-bit word using little-endian byte ordering:
//! - j=0: bits 0-7 (least significant byte)
//! - j=1: bits 8-15
//! - ...
//! - j=7: bits 56-63 (most significant byte)
//!
//! # Constraints
//!
//! The gate generates 2 AND constraints:
//! 1. Low byte extraction: `((word >> (8*j)) ⊕ z) ∧ 0xFF = 0`
//! 2. High bits zeroing: `z ∧ 0xFFFFFFFFFFFFFF00 = 0`

use binius_core::word::Word;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, empty, srl, xor2},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word(0xFF), Word(0xFFFFFFFFFFFFFF00u64)],
		n_in: 1,
		n_out: 1,
		n_aux: 0,
		n_scratch: 0,
		n_imm: 1,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		constants,
		inputs,
		outputs,
		imm,
		..
	} = data.gate_param();
	let [mask_ff, mask_high56] = constants else {
		unreachable!()
	};
	let [word] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [j] = imm else { unreachable!() };

	// Constraint 1: Low byte extraction
	// ((word >> (8*j)) ⊕ z) ∧ 0xFF = 0
	builder
		.and()
		.a(xor2(srl(*word, 8 * *j), *z))
		.b(*mask_ff)
		.c(empty())
		.build();

	// Constraint 2: High bits zeroing
	// z ∧ 0xFFFFFFFFFFFFFF00 = 0
	builder.and().a(*z).b(*mask_high56).c(empty()).build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam {
		inputs,
		outputs,
		imm,
		..
	} = data.gate_param();
	let [word] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [j] = imm else { unreachable!() };

	// Extract byte j: shift right by 8*j bits and mask to 8 bits
	builder.emit_slr(wire_to_reg(*z), wire_to_reg(*word), (8 * *j) as u8);
	builder.emit_mask_low(wire_to_reg(*z), wire_to_reg(*z), 8);
}
