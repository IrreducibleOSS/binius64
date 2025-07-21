/// Byte extraction from a 64-bit word.
///
/// Returns `z = (word >> (8*j)) & 0xFF` where j=0 is the least significant byte.
///
/// # Algorithm
///
/// Extracts byte j from a 64-bit word using little-endian byte ordering:
/// - j=0: bits 0-7 (least significant byte)
/// - j=1: bits 8-15
/// - ...
/// - j=7: bits 56-63 (most significant byte)
///
/// # Constraints
///
/// The gate generates 2 AND constraints:
/// 1. Low byte extraction: `((word >> (8*j)) ⊕ z) ∧ 0xFF = 0`
/// 2. High bits zeroing: `z ∧ 0xFFFFFFFFFFFFFF00 = 0`
use super::{Gate, GateData};
use crate::{
	compiler::circuit,
	constraint_system::{AndConstraint, ConstraintSystem, ShiftedValueIndex},
	word::Word,
};

pub fn constrain(
	_gate: Gate,
	data: &GateData,
	circuit: &circuit::Circuit,
	cs: &mut ConstraintSystem,
) {
	let [word, mask_ff, mask_high56] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };
	let [j] = data.immediates.as_slice() else {
		unreachable!()
	};

	let word_idx = circuit.witness_index(*word);
	let z_idx = circuit.witness_index(*z);
	let mask_ff_idx = circuit.witness_index(*mask_ff);
	let mask_high56_idx = circuit.witness_index(*mask_high56);

	// Constraint 1: Low byte extraction
	// ((word >> (8*j)) ⊕ z) ∧ 0xFF = 0
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::srl(word_idx, (8 * *j) as usize),
			ShiftedValueIndex::plain(z_idx),
		],
		[ShiftedValueIndex::plain(mask_ff_idx)],
		[],
	));

	// Constraint 2: High bits zeroing
	// z ∧ 0xFFFFFFFFFFFFFF00 = 0
	cs.add_and_constraint(AndConstraint::plain_abc([z_idx], [mask_high56_idx], []));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let [word, _mask_ff, _mask_high56] = data.inputs() else {
		unreachable!()
	};
	let [z] = data.outputs() else { unreachable!() };
	let [j] = data.immediates.as_slice() else {
		unreachable!()
	};

	let word_val = w[*word];
	// Extract byte j from the word (shift right by 8*j bits and mask to get the byte)
	let byte_val = (word_val.as_u64() >> (8 * *j)) & 0xFF;
	w[*z] = Word::from_u64(byte_val);
}
