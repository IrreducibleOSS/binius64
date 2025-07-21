/// 64-bit unsigned integer addition with carry propagation.
///
/// # Wires
///
/// - `a`, `b`: Input wires for the summands
/// - `cin` (carry-in): Input wire for the previous carry word. Only the MSB is used as the
///   actual carry bit
/// - `sum`: Output wire containing the resulting sum = a + b + carry_bit
/// - `cout` (carry-out): Output wire containing a carry word where each bit position indicates
///   whether a carry occurred at that position during the addition.
///
/// ## Carry-out Computation
///
/// The carry-out is computed as: `cout = (a & b) | ((a ^ b) & ¬sum)`
///
/// For example:
/// - `0x0000000000000003 + 0x0000000000000001 = 0x0000000000000004` with `cout =
///   0x0000000000000003` (carries at bits 0 and 1)
/// - `0xFFFFFFFFFFFFFFFF + 0x0000000000000001 = 0x0000000000000000` with `cout =
///   0xFFFFFFFFFFFFFFFF` (carries at all bit positions)
///
/// # Constraints
///
/// The gate generates two AND constraints:
///
/// 1. **Carry generation constraint**: Ensures correct carry propagation
/// 2. **Sum constraint**: Ensures the sum equals `a ^ b ^ (cout << 1) ^ cin_msb`
use crate::{
	compiler::{
		circuit,
		gate_graph::{Gate, GateData, GateParam},
	},
	constraint_system::{AndConstraint, ConstraintSystem, ShiftedValueIndex},
};

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
		..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [a, b, cin] = inputs else { unreachable!() };
	let [sum, cout] = outputs else { unreachable!() };

	let a_idx = circuit.witness_index(*a);
	let b_idx = circuit.witness_index(*b);
	let cin_idx = circuit.witness_index(*cin);
	let sum_idx = circuit.witness_index(*sum);
	let cout_idx = circuit.witness_index(*cout);
	let all_1_idx = circuit.witness_index(*all_1);

	let cout_sll_1 = ShiftedValueIndex::sll(cout_idx, 1);

	// Constraint 1: Carry propagation
	//
	// (a ⊕ (cout << 1) ⊕ cin_msb) ∧ (b ⊕ (cout << 1) ⊕ cin_msb) = cout ⊕ (cout << 1) ⊕ cin_msb
	let cin_msb = ShiftedValueIndex::srl(cin_idx, 63);
	let a_operands = vec![ShiftedValueIndex::plain(a_idx), cout_sll_1, cin_msb];
	let b_operands = vec![ShiftedValueIndex::plain(b_idx), cout_sll_1, cin_msb];
	let c_operands = vec![ShiftedValueIndex::plain(cout_idx), cout_sll_1, cin_msb];
	cs.add_and_constraint(AndConstraint::abc(a_operands, b_operands, c_operands));

	// Constraint 2: Sum equality
	//
	// (a ⊕ b ⊕ (cout << 1) ⊕ cin_msb) ∧ all-1 = sum
	let sum_operands = vec![
		ShiftedValueIndex::plain(a_idx),
		ShiftedValueIndex::plain(b_idx),
		ShiftedValueIndex::sll(cout_idx, 1),
		cin_msb,
	];
	cs.add_and_constraint(AndConstraint::abc(
		sum_operands,
		[ShiftedValueIndex::plain(all_1_idx)],
		[ShiftedValueIndex::plain(sum_idx)],
	));
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs, outputs, ..
	} = data.gate_param();
	let [a, b, cin] = inputs else { unreachable!() };
	let [sum, cout] = outputs else { unreachable!() };

	let a_val = w[*a];
	let b_val = w[*b];
	let carry_bit = w[*cin] >> 63;
	let (sum_val, carry_out) = a_val.iadd_cin_cout(b_val, carry_bit);

	w[*sum] = sum_val;
	w[*cout] = carry_out;
}
