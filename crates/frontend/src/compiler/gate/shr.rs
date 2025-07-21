/// Logical right shift.
///
/// Returns `z = x >> n`.
///
/// # Algorithm
///
/// Performs a logical right shift by `n` bits. The constraint system allows
/// referencing shifted versions of values directly without additional gates.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x >> n) ∧ all-1 = z`
use crate::{
	compiler::{
		circuit,
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	constraint_system::{AndConstraint, ConstraintSystem, ShiftedValueIndex},
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

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
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

	let x_idx = circuit.witness_index(*x);
	let z_idx = circuit.witness_index(*z);
	let all_1_idx = circuit.witness_index(*all_1);

	// Constraint: Logical right shift
	// (x >> n) ∧ all-1 = z
	cs.add_and_constraint(AndConstraint::abc(
		[ShiftedValueIndex::srl(x_idx, *n as usize)],
		[ShiftedValueIndex::plain(all_1_idx)],
		[ShiftedValueIndex::plain(z_idx)],
	));
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

	let result = w[*x] >> *n;
	w[*z] = result;
}
