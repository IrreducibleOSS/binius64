//! 64-bit rotate left.
//!
//! Returns `z = ((x << n) | (x >> (64 - n))) & MASK_64`
//!
//! # Algorithm
//!
//! Rotates a 64-bit value left by `n` positions:
//! 1. Shift left by n: `t1 = x << n` (bits n-63 move to positions 0-(63-n))
//! 2. Shift right by 64-n: `t2 = x >> (64-n)` (bits 0-(n-1) move to positions (64-n)-63)
//! 3. Combine with XOR: Since the shifted ranges don't overlap, `t1 | t2 = t1 ^ t2`
//! 4. Mask to 64 bits: `z = (t1 ^ t2) & MASK_64`
//!
//! The non-overlapping property is crucial: left-shifted bits occupy positions 0-(63-n),
//! while right-shifted bits occupy positions (64-n)-63, with no overlap.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `((x << n) ⊕ (x >> (64-n))) ∧ MASK_64 = z`

use binius_core::word::Word;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, sll, srl, xor2},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: 1,
		n_out: 1,
		n_internal: 0,
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
	let [mask64] = constants else { unreachable!() };
	let [x] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [n] = imm else { unreachable!() };

	// Constraint: Rotate left
	// ((x << n) ⊕ (x >> (64-n))) ∧ MASK_64 = z
	builder
		.and()
		.a(xor2(sll(*x, 64 - *n), srl(*x, *n)))
		.b(*mask64)
		.c(*z)
		.build();
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
	let [x] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [n] = imm else { unreachable!() };
	builder.emit_rotl(wire_to_reg(*z), wire_to_reg(*x), *n as u8);
}
