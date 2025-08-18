//! 64-bit equality test that returns all-1 if equal, all-0 if not equal.
//!
//! Returns `out_mask = all-1` if `x == y`, `all-0` otherwise.
//!
//! # Algorithm
//!
//! The gate exploits the property that when adding `all-1` to a value:
//! - If the value is 0: `0 + all-1 = all-1` with no carry out (MSB of cout = 0)
//! - If the value is non-zero: `value + all-1` wraps around with carry out (MSB of cout = 1)
//!
//! 1. Compute `diff = x ⊕ y` (which is 0 iff x == y)
//! 2. Compute carry bits `cout` from `diff + all-1` using the constraint: `(x ⊕ y ⊕ cin) ∧ (all-1 ⊕
//!    cin) = cin ⊕ cout` where `cin = cout << 1`
//! 3. The MSB of `cout` indicates the comparison result:
//!    - MSB = 0: no carry out, meaning `diff = 0`, so `x == y`
//!    - MSB = 1: carry out occurred, meaning `diff ≠ 0`, so `x ≠ y`
//! 4. Invert and broadcast the MSB: `out_mask = ¬(cout SRA 63)`
//!
//! # Constraints
//!
//! The gate generates two AND constraints:
//! 1. Carry propagation: `(x ⊕ y ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout`
//! 2. Mask generation: `out_mask = (cout SRA 63) ⊕ all-1`

use binius_core::word::Word;

use crate::compiler::{
	constraint_builder::{ConstraintBuilder, empty, sar, sll, xor2, xor3},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam, Wire},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ZERO], // Need zero constant for cin
		n_in: 3,
		n_out: 1,
		n_aux: 1,
		n_scratch: 3, // Need 3 scratch registers for intermediate computations
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		inputs,
		outputs,
		internal,
		..
	} = data.gate_param();
	let [x, y, all_1] = inputs else {
		unreachable!()
	};
	let [out_mask] = outputs else { unreachable!() };
	let [cout] = internal else { unreachable!() };

	let cin = sll(*cout, 1);

	// Constraint 1: Constrain carry-out
	// (x ⊕ y ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout
	builder
		.and()
		.a(xor3(*x, *y, cin))
		.b(xor2(*all_1, cin))
		.c(xor2(cin, *cout))
		.build();

	// Constraint 2: MSB propagation for equality mask
	// ((cout >> 63) ⊕ all-1 ⊕ out_mask) ∧ all-1 = 0
	builder
		.and()
		.a(xor3(sar(*cout, 63), *all_1, *out_mask))
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
	let [zero] = constants else { unreachable!() };
	let [x, y, all_1] = inputs else {
		unreachable!()
	};
	let [out_mask] = outputs else { unreachable!() };
	let [cout] = internal else { unreachable!() };
	let [scratch_diff, scratch_sum_unused, scratch_sar] = scratch else {
		unreachable!()
	};

	// Compute diff = x ^ y
	builder.emit_bxor(wire_to_reg(*scratch_diff), wire_to_reg(*x), wire_to_reg(*y));

	// Compute carry bits from all_1 + diff
	builder.emit_iadd_cin_cout(
		wire_to_reg(*scratch_sum_unused), // sum (unused)
		wire_to_reg(*cout),               // cout
		wire_to_reg(*all_1),              // all_1
		wire_to_reg(*scratch_diff),       // diff
		wire_to_reg(*zero),               // cin = 0
	);

	// Broadcast MSB: scratch_sar = cout >> 63 (arithmetic)
	builder.emit_sar(wire_to_reg(*scratch_sar), wire_to_reg(*cout), 63);

	// Invert: out_mask = scratch_sar ^ all_1
	builder.emit_bxor(wire_to_reg(*out_mask), wire_to_reg(*scratch_sar), wire_to_reg(*all_1));
}
