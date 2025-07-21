/// 64-bit equality test that returns all-1 if equal, all-0 if not equal.
///
/// Returns `out_mask = all-1` if `x == y`, `all-0` otherwise.
///
/// # Algorithm
///
/// The gate exploits the property that when adding `all-1` to a value:
/// - If the value is 0: `0 + all-1 = all-1` with no carry out (MSB of cout = 0)
/// - If the value is non-zero: `value + all-1` wraps around with carry out (MSB of cout = 1)
///
/// 1. Compute `diff = x ⊕ y` (which is 0 iff x == y)
/// 2. Compute carry bits `cout` from `diff + all-1` using the constraint: `(x ⊕ y ⊕ cin) ∧
///    (all-1 ⊕ cin) = cin ⊕ cout` where `cin = cout << 1`
/// 3. The MSB of `cout` indicates the comparison result:
///    - MSB = 0: no carry out, meaning `diff = 0`, so `x == y`
///    - MSB = 1: carry out occurred, meaning `diff ≠ 0`, so `x ≠ y`
/// 4. Invert and broadcast the MSB: `out_mask = ¬(cout SRA 63)`
///
/// # Constraints
///
/// The gate generates two AND constraints:
/// 1. Carry propagation: `(x ⊕ y ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout`
/// 2. Mask generation: `out_mask = (cout SRA 63) ⊕ all-1`
use crate::{
	compiler::{
		circuit,
		gate_graph::{Gate, GateData, GateParam},
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
	let GateParam {
		inputs,
		outputs,
		internal,
		..
	} = data.gate_param();
	let [x, y, all_1] = inputs else {
		unreachable!()
	};
	let [out_mask] = outputs else { unreachable!() };
	let [cout] = internal else { unreachable!() };

	let x_idx = circuit.witness_index(*x);
	let y_idx = circuit.witness_index(*y);
	let out_mask_idx = circuit.witness_index(*out_mask);
	let cout_idx = circuit.witness_index(*cout);
	let all_1_idx = circuit.witness_index(*all_1);

	let cin = ShiftedValueIndex::sll(cout_idx, 1);

	// Constraint 1: Constrain carry-out
	// (x ⊕ y ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::plain(x_idx),
			ShiftedValueIndex::plain(y_idx),
			cin,
		],
		[ShiftedValueIndex::plain(all_1_idx), cin],
		[cin, ShiftedValueIndex::plain(cout_idx)],
	));

	// Constraint 2: MSB propagation for equality mask
	// ((cout >> 63) ⊕ all-1 ⊕ out_mask) ∧ all-1 = 0
	cs.add_and_constraint(AndConstraint::abc(
		[
			ShiftedValueIndex::sar(cout_idx, 63),
			ShiftedValueIndex::plain(all_1_idx),
			ShiftedValueIndex::plain(out_mask_idx),
		],
		[ShiftedValueIndex::plain(all_1_idx)],
		[],
	));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs,
		outputs,
		internal,
		..
	} = data.gate_param();
	let [x, y, _all_1] = inputs else {
		unreachable!()
	};
	let [out_mask] = outputs else { unreachable!() };
	let [cout] = internal else { unreachable!() };

	let diff = w[*x] ^ w[*y];
	let (_, cout_val) = Word::ALL_ONE.iadd_cin_cout(diff, Word::ZERO);
	w[*cout] = cout_val;
	w[*out_mask] = !cout_val.sar(63);
}
