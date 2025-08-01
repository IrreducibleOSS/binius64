/// 32-bit unsigned integer addition with carry propagation.
///
/// Returns `z = (x + y) & MASK_32` and `cout` containing carry bits.
///
/// # Algorithm
///
/// Performs 32-bit addition by computing the full 64-bit result and masking:
/// 1. Compute carry bits `cout` from `x + y` using carry propagation
/// 2. Extract the lower 32 bits: `z = (x ⊕ y ⊕ (cout << 1)) ∧ MASK_32`
///
/// # Constraints
///
/// The gate generates 2 AND constraints:
/// 1. Carry propagation: `(x ⊕ (cout << 1)) ∧ (y ⊕ (cout << 1)) = cout ⊕ (cout << 1)`
/// 2. Result masking: `(x ⊕ y ⊕ (cout << 1)) ∧ MASK_32 = z`
use crate::{
	compiler::{
		circuit,
		constraint_builder::{ConstraintBuilder, sll, xor2, xor3},
		gate::opcode::OpcodeShape,
		gate_graph::{Gate, GateData, GateParam},
	},
	word::Word,
};

pub fn shape() -> OpcodeShape {
	OpcodeShape {
		const_in: &[Word::MASK_32],
		n_in: 2,
		n_out: 1,
		n_internal: 1,
		n_imm: 0,
	}
}

pub fn constrain(_gate: Gate, data: &GateData, builder: &mut ConstraintBuilder) {
	let GateParam {
		constants,
		inputs,
		outputs,
		internal,
		..
	} = data.gate_param();
	let [mask32] = constants else { unreachable!() };
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [cout] = internal else { unreachable!() };

	let cout_sll_1 = sll(*cout, 1);

	// Constraint 1: Carry propagation
	//
	// (x ⊕ (cout << 1)) ∧ (y ⊕ (cout << 1)) = cout ⊕ (cout << 1)
	builder
		.and()
		.a(xor2(*x, cout_sll_1))
		.b(xor2(*y, cout_sll_1))
		.c(xor2(*cout, cout_sll_1))
		.build();

	// Constraint 2: Result masking
	//
	// (x ⊕ y ⊕ (cout << 1)) ∧ MASK_32 = z
	builder
		.and()
		.a(xor3(*x, *y, cout_sll_1))
		.b(*mask32)
		.c(*z)
		.build();
}

pub fn evaluate(_gate: Gate, data: &GateData, w: &mut circuit::WitnessFiller) {
	let GateParam {
		inputs,
		outputs,
		internal,
		..
	} = data.gate_param();
	let [x, y] = inputs else { unreachable!() };
	let [z] = outputs else { unreachable!() };
	let [cout] = internal else { unreachable!() };

	let (sum, carry) = w[*x].iadd_cout_32(w[*y]);
	w[*z] = sum;
	w[*cout] = carry;
}
