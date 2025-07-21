/// Imul gate implements 64-bit × 64-bit → 128-bit unsigned multiplication.
/// Uses the MulConstraint: X * Y = (HI << 64) | LO
use crate::{
	compiler::{
		circuit,
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	constraint_system::{ConstraintSystem, MulConstraint, ShiftedValueIndex},
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

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [hi, lo] = outputs else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let hi_idx = circuit.witness_index(*hi);
	let lo_idx = circuit.witness_index(*lo);

	// Create MulConstraint: X * Y = (HI << 64) | LO
	let mul_constraint = MulConstraint {
		a: vec![ShiftedValueIndex::plain(x_idx)],
		b: vec![ShiftedValueIndex::plain(y_idx)],
		lo: vec![ShiftedValueIndex::plain(lo_idx)],
		hi: vec![ShiftedValueIndex::plain(hi_idx)],
	};

	cs.add_mul_constraint(mul_constraint);
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
