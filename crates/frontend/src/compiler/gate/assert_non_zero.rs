//! Assert that a wire isn't zero.
//!
//! Enforces `x ≠ 0`.
//!
//! # Algorithm
//!
//! The idea is similar to `icmp_eq`, but actually simpler.
//! First off, we only have one operand, not two;
//! secondly, we don't need to negate the MSB of the result.
//!
//! The gate exploits the property that when adding `all-1` to a value:
//! - If the value is 0: `0 + all-1 = all-1` with no carry out (MSB of cout = 0)
//! - If the value is non-zero: `value + all-1` wraps around with carry out (MSB of cout = 1)
//!
//! The algorithm is as follows:
//! 1. Compute carry bits `cout` from `x + all-1` using the constraint: `(x ⊕ cin) ∧ (all-1 ⊕ cin) =
//!    cin ⊕ cout` where `cin = cout << 1`
//! 2. The MSB of `cout` tells us whether x ≠ 0; i.e.,
//!    - MSB = 0: no carry out, meaning `x = 0`
//!    - MSB = 1: carry out occurred, meaning `x ≠ 0`
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `(x ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout`

use binius_core::word::Word;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, sll, xor2},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
	pathspec::PathSpec,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE, Word::ZERO], // Need zero constant for cin
		n_in: 1,
		n_out: 1,
		n_aux: 0,
		n_scratch: 1,
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
	let [x] = inputs else { unreachable!() };
	let [cout] = outputs else { unreachable!() };

	let cin = sll(*cout, 1);

	// Constraint 1: Constrain carry-out
	// (x ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout
	builder
		.and()
		.a(xor2(*x, cin))
		.b(xor2(*all_1, cin))
		.c(xor2(cin, *cout))
		.build();
}

pub fn emit_eval_bytecode(
	_gate: Gate,
	data: &GateData,
	assertion_path: PathSpec,
	builder: &mut crate::compiler::eval_form::BytecodeBuilder,
	wire_to_reg: impl Fn(Wire) -> u32,
) {
	let GateParam {
		constants,
		inputs,
		outputs,
		scratch,
		..
	} = data.gate_param();
	let [all_1, zero] = constants else {
		unreachable!()
	};
	let [x] = inputs else { unreachable!() };
	let [cout] = outputs else { unreachable!() };
	let [scratch_sum_unused] = scratch else {
		unreachable!()
	};

	// Compute carry bits from all_1 + diff
	builder.emit_iadd_cin_cout(
		wire_to_reg(*scratch_sum_unused), // sum (unused)
		wire_to_reg(*cout),               // cout
		wire_to_reg(*all_1),              // all_1
		wire_to_reg(*x),                  // x
		wire_to_reg(*zero),               // cin = 0
	);

	builder.emit_assert_non_zero(wire_to_reg(*cout), assertion_path.as_u32());
}
