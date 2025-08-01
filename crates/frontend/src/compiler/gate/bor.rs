/// Bitwise OR operation.
///
/// Returns `z = x | y`.
///
/// # Algorithm
///
/// Computes the bitwise OR using De Morgan's law: `x | y = ¬(¬x ∧ ¬y)`.
/// This is implemented as `x ∧ y = (x ⊕ y ⊕ z)`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ y = x ⊕ y ⊕ z`
use crate::compiler::{
	circuit,
	constraint_builder::{ConstraintBuilder, xor3},
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

	// Constraint: Bitwise OR
	//
	// x ∧ y = x ⊕ y ⊕ z
	builder.and().a(*x).b(*y).c(xor3(*x, *y, *z)).build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };

	w[*z] = w[*x] | w[*y];
}
