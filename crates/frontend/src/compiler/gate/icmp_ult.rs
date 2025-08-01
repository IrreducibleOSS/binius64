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
		constraint_builder::{ConstraintBuilder, empty, sar, sll, xor2, xor3},
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	word::Word,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::ALL_ONE],
		n_in: 2,
		n_out: 1,
		n_internal: 1,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		inputs,
		outputs,
		internal,
		constants,
		..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [x, y] = inputs else { unreachable!() };
	let [out_mask] = outputs else { unreachable!() };
	let [bout] = internal else { unreachable!() };

	// Constraint 1: Carry propagation for comparison
	// ((x ⊕ all-1) ⊕ (bout << 1)) ∧ (y ⊕ (bout << 1)) = bout ⊕ (bout << 1)
	builder
		.and()
		.a(xor3(*x, *all_1, sll(*bout, 1)))
		.b(xor2(*y, sll(*bout, 1)))
		.c(xor2(*bout, sll(*bout, 1)))
		.build();

	// Constraint 2: MSB broadcast
	// ((bout >> 63) ⊕ out_mask) ∧ all-1 = 0
	builder
		.and()
		.a(xor2(sar(*bout, 63), *out_mask))
		.b(*all_1)
		.c(empty())
		.build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		constants,
		inputs,
		outputs,
		internal,
		..
	} = data.gate_param();
	let [all_1] = constants else { unreachable!() };
	let [x, y] = inputs else { unreachable!() };
	let [out_mask] = outputs else { unreachable!() };
	let [bout] = internal else { unreachable!() };

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
