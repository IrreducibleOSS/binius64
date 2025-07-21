/// Unsigned less-than test returning a mask.
///
/// Returns `out_mask = all-1` if `x < y`, `all-0` otherwise.
///
/// # Algorithm
///
/// The gate computes `x < y` by checking if there's a borrow when computing `x - y`.
/// This is done by computing `¬x + y` and checking if it carries out (≥ 2^64).
///
/// 1. Compute carry bits `bout` from `¬x + y` using the constraint: `(¬x ⊕ bin) ∧ (y ⊕ bin) =
///    bin ⊕ bout` where `bin = bout << 1`
/// 2. The MSB of `bout` indicates the comparison result:
///    - MSB = 1: carry out occurred, meaning `x < y`
///    - MSB = 0: no carry out, meaning `x ≥ y`
/// 3. Broadcast the MSB to all bits: `out_mask = bout SRA 63`
///
/// # Constraints
///
/// The gate generates 2 AND constraints:
/// 1. Borrow propagation: `(¬x ⊕ bin) ∧ (y ⊕ bin) = bin ⊕ bout`
/// 2. Mask generation: `out_mask = bout SRA 63`
use crate::{
	compiler::{
		circuit,
		gate_graph::{Gate, GateData},
	},
	constraint_system::{AndConstraint, ConstraintSystem, ShiftedValueIndex},
	word::Word,
};

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let [x, y, all_1] = data.inputs() else {
		unreachable!()
	};
	let [out_mask, bout] = data.outputs() else {
		unreachable!()
	};

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let out_mask_idx = circuit.witness_index(*out_mask);
	let bout_idx = circuit.witness_index(*bout);
	let all_1_idx = circuit.witness_index(*all_1);

	// Constraint 1: Carry propagation for comparison
	// ((x ⊕ all-1) ⊕ (bout << 1)) ∧ (y ⊕ (bout << 1)) = bout ⊕ (bout << 1)
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::plain(x_idx),
			ShiftedValueIndex::plain(all_1_idx),
			ShiftedValueIndex::sll(bout_idx, 1),
		],
		[
			ShiftedValueIndex::plain(y_idx),
			ShiftedValueIndex::sll(bout_idx, 1),
		],
		[
			ShiftedValueIndex::plain(bout_idx),
			ShiftedValueIndex::sll(bout_idx, 1),
		],
	));

	// Constraint 2: MSB broadcast
	// ((bout >> 63) ⊕ out_mask) ∧ all-1 = 0
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::sar(bout_idx, 63),
			ShiftedValueIndex::plain(out_mask_idx),
		],
		[ShiftedValueIndex::plain(all_1_idx)],
		[],
	));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [x, y, all_1] = data.inputs() else {
		unreachable!()
	};
	let [out_mask, bout] = data.outputs() else {
		unreachable!()
	};

	let x_val = w[*x];
	let y_val = w[*y];
	let all_1_val = w[*all_1];

	// Compute ¬x for the comparison
	let nx = all_1_val ^ x_val;
	// Compute carry bits from ¬x + y using standard carry propagation
	let (_, bout_val) = nx.iadd_cin_cout(y_val, Word::ZERO);
	w[*bout] = bout_val;

	// Broadcast the MSB of bout to all bits to create the comparison mask
	let Word(bout_val_raw) = bout_val;
	let bout_msb_broadcast = (bout_val_raw as i64 >> 63) as u64;
	let out_mask_val = Word(bout_msb_broadcast);
	w[*out_mask] = out_mask_val;
}
