/// Logical left shift.
///
/// Returns `z = x << n`.
///
/// # Algorithm
///
/// Performs a logical left shift by `n` bits. The constraint system allows
/// referencing shifted versions of values directly without additional gates.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x << n) ∧ all-1 = z`
use crate::{
	compiler::{
		circuit,
		constraint_builder::{ConstraintBuilder, sll},
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	word::Word,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: 1,
		n_out: 1,
		n_internal: 0,
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
	let [all_1] = constants else { unreachable!() };
	let [x] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [n] = imm else { unreachable!() };

	// Constraint: Logical left shift
	// (x << n) ∧ all-1 = z
	builder.and().a(sll(*x, *n)).b(*all_1).c(*z).build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs,
		outputs,
		imm,
		..
	} = data.gate_param();
	let [x] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [n] = imm else { unreachable!() };

	let result = w[*x] << *n;
	w[*z] = result;
}
