use super::{Circuit, CircuitBuilder, Wire, WitnessFiller};
use crate::{
	constraint_system::{AndConstraint, ConstraintSystem, MulConstraint, ShiftedValueIndex},
	word::Word,
};

pub trait Gate {
	fn populate_wire_witness(&self, w: &mut WitnessFiller);
	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem);
}

pub struct Band {
	pub a: Wire,
	pub b: Wire,
	pub c: Wire,
}

impl Band {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let c = builder.add_witness();
		Self { a, b, c }
	}
}

impl Gate for Band {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		w[self.c] = w[self.a] & w[self.b];
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let c = circuit.witness_index(self.c);
		cs.add_and_constraint(AndConstraint::plain_abc([a], [b], [c]));
	}
}

pub struct Bxor {
	pub a: Wire,
	pub b: Wire,
	pub c: Wire,
}

impl Bxor {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let c = builder.add_witness();
		Self { a, b, c }
	}
}

impl Gate for Bxor {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		w[self.c] = w[self.a] ^ w[self.b];
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let c = circuit.witness_index(self.c);
		cs.add_and_constraint(AndConstraint::plain_abc([a, b], [], [c]));
	}
}

pub struct Bor {
	pub a: Wire,
	pub b: Wire,
	pub c: Wire,
}

impl Bor {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let c = builder.add_witness();
		Self { a, b, c }
	}
}

impl Gate for Bor {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		w[self.c] = w[self.a] | w[self.b];
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let c = circuit.witness_index(self.c);
		cs.add_and_constraint(AndConstraint::plain_abc([a], [b], [a, b, c]));
	}
}

pub struct Iadd32 {
	pub a: Wire,
	pub b: Wire,
	pub c: Wire,
	pub cout: Wire,
	pub mask32: Wire,
}

impl Iadd32 {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let c = builder.add_witness();
		let cout = builder.add_witness();
		let mask32 = builder.add_constant(Word::MASK_32);
		Self {
			a,
			b,
			c,
			cout,
			mask32,
		}
	}
}

impl Gate for Iadd32 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let (sum, carry) = w[self.a].iadd_32(w[self.b]);

		w[self.c] = sum;
		w[self.cout] = carry;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let c = circuit.witness_index(self.c);
		let cout = circuit.witness_index(self.cout);
		let mask32 = circuit.witness_index(self.mask32);

		// (x XOR (cout << 1)) AND (y XOR (cout << 1)) = (cout << 1) XOR cout
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(a), ShiftedValueIndex::sll(cout, 1)],
			[ShiftedValueIndex::plain(b), ShiftedValueIndex::sll(cout, 1)],
			[
				ShiftedValueIndex::plain(cout),
				ShiftedValueIndex::sll(cout, 1),
			],
		));

		// (x XOR y XOR (cout << 1)) AND M32 = z
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::plain(a),
				ShiftedValueIndex::plain(b),
				ShiftedValueIndex::sll(cout, 1),
			],
			[ShiftedValueIndex::plain(mask32)],
			[ShiftedValueIndex::plain(c)],
		));
	}
}

pub struct Shr32 {
	pub a: Wire,
	pub c: Wire,
	pub mask32: Wire,
	pub n: u32,
}

impl Shr32 {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let c = builder.add_witness();
		let mask32 = builder.add_constant(Word::MASK_32);
		Self { a, c, mask32, n }
	}
}

impl Gate for Shr32 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.a].shr_32(self.n);
		w[self.c] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let c = circuit.witness_index(self.c);
		let mask32 = circuit.witness_index(self.mask32);

		// SHR = AND(srl(x, n), M32)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::srl(a, self.n as usize)],
			[ShiftedValueIndex::plain(mask32)],
			[ShiftedValueIndex::plain(c)],
		));
	}
}

pub struct Rotr32 {
	pub a: Wire,
	pub c: Wire,
	pub mask32: Wire,
	pub n: u32,
}

impl Rotr32 {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let c = builder.add_witness();
		let mask32 = builder.add_constant(Word::MASK_32);
		Self { a, c, mask32, n }
	}
}

impl Gate for Rotr32 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.a].rotr_32(self.n);
		w[self.c] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let c = circuit.witness_index(self.c);
		let mask32 = circuit.witness_index(self.mask32);

		// ROTR(x, n):
		//     t1 = srl(x, n),
		//     t2 = sll(x, 32-n),
		//     r = OR(t1, t2),
		//     return AND(r, M32)
		//
		// This translates to:
		//
		// AND(OR(srl(x, n), sll(x, 32-n)), M32) = c
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::srl(a, self.n as usize),
				ShiftedValueIndex::sll(a, (32 - self.n) as usize),
			],
			[ShiftedValueIndex::plain(mask32)],
			[ShiftedValueIndex::plain(c)],
		));
	}
}

pub struct AssertEq {
	pub x: Wire,
	pub y: Wire,
}

impl AssertEq {
	pub fn new(x: Wire, y: Wire) -> Self {
		Self { x, y }
	}
}

impl Gate for AssertEq {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		if w[self.x] != w[self.y] {
			w.flag_assertion_failed();
		}
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);

		cs.add_and_constraint(AndConstraint::plain_abc([x], [], [y]));
	}
}

/// Assert0 enforces that a wire equals zero using a single AND constraint.
/// Pattern: AND(a, ALL_1, 0) which constrains a = 0
pub struct Assert0 {
	pub a: Wire,
	pub all_1: Wire,
}

impl Assert0 {
	pub fn new(builder: &CircuitBuilder, a: Wire) -> Self {
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { a, all_1 }
	}
}

impl Gate for Assert0 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		// The constraint is: a & ALL_1 = 0, which means a must be 0
		if w[self.a] != Word::ZERO {
			w.flag_assertion_failed();
		}
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let all_1 = circuit.witness_index(self.all_1);

		// Constraint: AND(a, ALL_1, 0) => a & ALL_1 = 0 => a = 0
		cs.add_and_constraint(AndConstraint::plain_abc([a], [all_1], []));
	}
}

/// Imul gate implements 64-bit × 64-bit → 128-bit unsigned multiplication.
/// Uses the MulConstraint: A * B = (HI << 64) | LO
pub struct Imul {
	pub a: Wire,
	pub b: Wire,
	pub hi: Wire,
	pub lo: Wire,
}

impl Imul {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let hi = builder.add_witness();
		let lo = builder.add_witness();
		Self { a, b, hi, lo }
	}
}

impl Gate for Imul {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let (hi, lo) = w[self.a].imul(w[self.b]);
		w[self.hi] = hi;
		w[self.lo] = lo;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let hi = circuit.witness_index(self.hi);
		let lo = circuit.witness_index(self.lo);

		// Create MulConstraint: A * B = (HI << 64) | LO
		let mul_constraint = MulConstraint {
			a: vec![ShiftedValueIndex::plain(a)],
			b: vec![ShiftedValueIndex::plain(b)],
			hi: vec![ShiftedValueIndex::plain(hi)],
			lo: vec![ShiftedValueIndex::plain(lo)],
		};

		cs.add_mul_constraint(mul_constraint);
	}
}
