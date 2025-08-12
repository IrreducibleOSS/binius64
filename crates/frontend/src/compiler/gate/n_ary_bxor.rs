//! n-ary Bitwise XOR operation.
//!
//! Returns `z = x1 ^ x2 ^ ... ^ xn`.
//!
//! # Algorithm
//!
//! Computes the bitwise XOR using the identity: `x1 ^ x2 ^ ... ^ xn = ¬(x1 ∧ x2 ∧ ... ∧ xn)`.
//! This is implemented as `(x1 ⊕ x2 ⊕ ... ⊕ xn) ∧ all-1 = z`.
//!
//! # Constraints
//!
//! The gate generates 1 AND constraint:
//! - `(x1 ⊕ x2 ⊕ ... ⊕ xn) ∧ all-1 = z`

use binius_core::word::Word;

use crate::compiler::{
	circuit,
	constraint_builder::{ConstraintBuilder, n_ary_xor},
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam},
};

pub fn shape(dimensions: &[usize]) -> OpcodeShape {
	let [n_inputs] = dimensions else {
		unreachable!("n-ary XOR requires dimension for number of inputs")
	};
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: *n_inputs,
		n_out: 1,
		n_internal: 0,
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

	// (x1 ⊕ x2 ⊕ ... ⊕ xn) ∧ all-1 = z
	// Build the XOR expression for n inputs
	builder.and().a(n_ary_xor(inputs)).b(*all_1).c(*z).build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [z] = outputs else { unreachable!() };

	// Compute n-ary XOR
	let result = inputs.iter().fold(Word(0), |acc, &input| acc ^ w[input]);
	w[*z] = result;
}
