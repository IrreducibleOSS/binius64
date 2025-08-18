//! Unsigned less-than test returning a mask.
//!
//! Returns `out_mask = all-1` if `x < y`, `all-0` otherwise.
//!
//! # Algorithm
//!
//! The gate computes `x < y` by checking if there's a borrow when computing `x - y`.
//! This is done by computing `¬x + y` and checking if it carries out (≥ 2^64).
//!
//! 1. Compute carry bits `bout` from `¬x + y` using the constraint: `(¬x ⊕ bin) ∧ (y ⊕ bin) = bin ⊕
//!    bout` where `bin = bout << 1`
//! 2. The MSB of `bout` indicates the comparison result:
//!    - MSB = 1: carry out occurred, meaning `x < y`
//!    - MSB = 0: no carry out, meaning `x ≥ y`
//! 3. Broadcast the MSB to all bits: `out_mask = bout SRA 63`
//!
//! # Constraints
//!
//! The gate generates 2 AND constraints:
//! 1. Borrow propagation: `(¬x ⊕ bin) ∧ (y ⊕ bin) = bin ⊕ bout`
//! 2. Mask generation: `out_mask = bout SRA 63`

use binius_core::word::Word;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, empty, sar, sll, xor2, xor3},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE, Word::ZERO], // Need all_1 and zero constants
		n_in: 2,
		n_out: 1,
		n_aux: 1,
		n_scratch: 2, // Need 2 scratch registers for intermediate computations
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		inputs,
		outputs,
		internal,
		constants,
		..
	} = data.gate_param();
	let [all_1, _zero] = constants else {
		unreachable!()
	};
	let [x, y] = inputs else { unreachable!() };
	let [out_mask] = outputs else { unreachable!() };
	let [bout] = internal else { unreachable!() };

	// Constraint 1: Carry propagation for comparison
	// ((x ⊕ all-1) ⊕ (bout << 1)) ∧ (y ⊕ (bout << 1)) = bout ⊕ (bout << 1)
	builder
		.and()
		.a(xor3(*x, *all_1, sll(*bout, 1)))
		.b(xor2(*y, sll(*bout, 1)))
		.c(xor2(*bout, sll(*bout, 1)))
		.build();

	// Constraint 2: MSB broadcast
	// ((bout >> 63) ⊕ out_mask) ∧ all-1 = 0
	builder
		.and()
		.a(xor2(sar(*bout, 63), *out_mask))
		.b(*all_1)
		.c(empty())
		.build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam {
		constants,
		inputs,
		outputs,
		internal,
		scratch,
		..
	} = data.gate_param();
	let [all_1, zero] = constants else {
		unreachable!()
	};
	let [x, y] = inputs else { unreachable!() };
	let [out_mask] = outputs else { unreachable!() };
	let [bout] = internal else { unreachable!() };
	let [scratch_nx, scratch_sum_unused] = scratch else {
		unreachable!()
	};

	// Compute ¬x (x XOR all_1)
	builder.emit_bxor(wire_to_reg(*scratch_nx), wire_to_reg(*x), wire_to_reg(*all_1));

	// Compute carry bits from ¬x + y
	builder.emit_iadd_cin_cout(
		wire_to_reg(*scratch_sum_unused), // sum (unused)
		wire_to_reg(*bout),               // cout
		wire_to_reg(*scratch_nx),         // ¬x
		wire_to_reg(*y),                  // y
		wire_to_reg(*zero),               // cin = 0
	);

	// Broadcast MSB: out_mask = bout >> 63 (arithmetic)
	builder.emit_sar(wire_to_reg(*out_mask), wire_to_reg(*bout), 63);
}
