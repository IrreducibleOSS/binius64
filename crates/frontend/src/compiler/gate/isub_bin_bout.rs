use binius_core::word::Word;

use crate::compiler::{
	circuit,
	constraint_builder::{ConstraintBuilder, sll, srl, xor3, xor4},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: 3,
		n_out: 2,
		n_internal: 1,
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
	let [a, b, bin] = inputs else { unreachable!() };
	let [diff, bout] = outputs else {
		unreachable!()
	};

	let bout_sll_1 = sll(*bout, 1);
	let bin_msb = srl(*bin, 63);

	// Constraint 1: Borrow propagation
	//
	// (¬a ⊕ (bout << 1) ⊕ bin_msb) ∧ (b ⊕ (bout << 1) ⊕ bin_msb) = bout ⊕ (bout << 1) ⊕ bin_msb
	builder
		.and()
		.a(xor4(*all_1, *a, bout_sll_1, bin_msb))
		.b(xor3(*b, bout_sll_1, bin_msb))
		.c(xor3(*bout, bout_sll_1, bin_msb))
		.build();

	// Constraint 2: Diff equality
	//
	// (a ⊕ b ⊕ (bout << 1) ⊕ bin_msb) ∧ all-1 = diff
	builder
		.and()
		.a(xor4(*a, *b, bout_sll_1, bin_msb))
		.b(*all_1)
		.c(*diff)
		.build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [a, b, bin] = inputs else { unreachable!() };
	let [diff, bout] = outputs else {
		unreachable!()
	};

	let a_val = w[*a];
	let b_val = w[*b];
	let borrow_bit = w[*bin] >> 63;
	let (diff_val, borrow_out) = a_val.isub_bin_bout(b_val, borrow_bit);

	w[*diff] = diff_val;
	w[*bout] = borrow_out;
}
