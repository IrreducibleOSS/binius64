/// Imul gate implements 64-bit × 64-bit → 128-bit unsigned multiplication.
/// Uses the MulConstraint: X * Y = (HI << 64) | LO
use crate::compiler::{
	circuit,
	constraint_builder::ConstraintBuilder,
	gate::opcode::OpcodeShape,
	gate_graph::{Gate, GateData, GateParam},
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[],
		n_in: 2,
		n_out: 2,
		n_internal: 0,
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
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [hi, lo] = outputs else { unreachable!() };

	let (hi_val, lo_val) = w[*x].imul(w[*y]);
	w[*hi] = hi_val;
	w[*lo] = lo_val;
}
