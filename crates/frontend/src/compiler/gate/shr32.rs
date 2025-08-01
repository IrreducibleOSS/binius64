/// 32-bit logical right shift.
///
/// Returns `z = (x >> n) & MASK_32`.
///
/// # Algorithm
///
/// Shifts the input right by `n` bits and masks to 32 bits.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x >> n) ∧ MASK_32 = z`
use crate::{
	compiler::{
		circuit,
		constraint_builder::{ConstraintBuilder, srl},
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	word::Word,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::MASK_32],
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
	let [mask32] = constants else { unreachable!() };
	let [x] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [n] = imm else { unreachable!() };

	// Constraint: Shift right with masking
	// (x >> n) ∧ MASK_32 = z
	builder.and().a(srl(*x, *n)).b(*mask32).c(*z).build();
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

	let result = w[*x].shr_32(*n);
	w[*z] = result;
}
