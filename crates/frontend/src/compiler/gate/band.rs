/// Bitwise AND operation.
///
/// Returns `z = x & y`.
///
/// # Algorithm
///
/// Computes the bitwise AND of two 64-bit words using a single AND constraint.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ y = z`
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
		n_out: 1,
		n_internal: 0,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	// Constraint: Bitwise AND
	//
	// x ∧ y = z
	builder.and().a(*x).b(*y).c(*z).build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	w[*z] = w[*x] & w[*y];
}
