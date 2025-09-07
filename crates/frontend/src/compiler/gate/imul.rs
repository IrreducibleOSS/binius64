// Copyright 2025 Irreducible Inc.
//! Imul gate implements 64-bit × 64-bit → 128-bit unsigned multiplication.
//! Uses the MulConstraint: X * Y = (HI << 64) | LO

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, sll},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 2,
		n_out: 2,
		n_aux: 0,
		n_scratch: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [hi, lo] = outputs else { unreachable!() };

	// Create MulConstraint: X * Y = (HI << 64) | LO
	builder.mul().a(*x).b(*y).hi(*hi).lo(*lo).build();

	// Security fix: IntMul reduction proves x*y ≡ lo + 2^64*hi (mod 2^128-1), but we need (mod
	// 2^128). Attack: If x=0 or y=0, malicious prover sets lo=hi=2^64-1, giving lo + 2^64*hi =
	// 2^128-1 ≡ 0 (mod 2^128-1). This passes the IntMul check but violates the intended x*y = lo +
	// 2^64*hi over integers.
	//
	// Fix: Check LSB multiplication x[0] * y[0] = lo[0].
	// If x=0 or y=0, then x[0]*y[0] = 0, so lo[0] must be 0. But the attack has lo[0] = 1, failing
	// this check.
	//
	// Implementation: Shift LSBs to MSB position for AND constraint.
	builder
		.and()
		.a(sll(*x, 63))
		.b(sll(*y, 63))
		.c(sll(*lo, 63))
		.build();
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
	let [x, y] = inputs else { unreachable!() };
	let [hi, lo] = outputs else { unreachable!() };
	builder.emit_imul(wire_to_reg(*hi), wire_to_reg(*lo), wire_to_reg(*x), wire_to_reg(*y));
}
