/// 32-bit rotate right.
///
/// Returns `z = ((x >> n) | (x << (32-n))) & MASK_32`.
///
/// # Algorithm
///
/// Rotates a 32-bit value right by `n` positions:
/// 1. Shift right by n: `t1 = x >> n` (bits n-31 move to positions 0-(31-n))
/// 2. Shift left by 32-n: `t2 = x << (32-n)` (bits 0-(n-1) move to positions (32-n)-31)
/// 3. Combine with XOR: Since the shifted ranges don't overlap, `t1 | t2 = t1 ^ t2`
/// 4. Mask to 32 bits: `z = (t1 ^ t2) & MASK_32`
///
/// The non-overlapping property is crucial: right-shifted bits occupy positions 0-(31-n),
/// while left-shifted bits occupy positions (32-n)-31, with no overlap.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `((x >> n) ⊕ (x << (32-n))) ∧ MASK_32 = z`
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
		const_in: &[Word::MASK_32],
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
	let [mask32] = constants else { unreachable!() };
	let [x] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [n] = imm else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let z_idx = circuit.witness_index(*z);
	let mask32_idx = circuit.witness_index(*mask32);

	// Constraint: Rotate right
	// ((x >> n) ⊕ (x << (32-n))) ∧ MASK_32 = z
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::srl(x_idx, *n as usize),
			ShiftedValueIndex::sll(x_idx, (32 - *n) as usize),
		],
		[ShiftedValueIndex::plain(mask32_idx)],
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

	let result = w[*x].rotr_32(*n);
	w[*z] = result;
}
