/// Bitwise XOR operation.
///
/// Returns `z = x ^ y`.
///
/// # Algorithm
///
/// Computes the bitwise XOR using the identity: `x ^ y = ¬(x ∧ y)`.
/// This is implemented as `(x ⊕ y) ∧ all-1 = z`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x ⊕ y) ∧ all-1 = z`
use crate::{
	compiler::{
		circuit,
		constraint_builder::{ConstraintBuilder, xor2},
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	word::Word,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: 2,
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
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	// Constraint: Bitwise XOR
	//
	// (x ⊕ y) ∧ all-1 = z
	builder.and().a(xor2(*x, *y)).b(*all_1).c(*z).build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	w[*z] = w[*x] ^ w[*y];
}
