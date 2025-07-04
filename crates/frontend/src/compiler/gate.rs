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
	pub name: String,
	pub x: Wire,
	pub y: Wire,
}

impl AssertEq {
	pub fn new(name: String, x: Wire, y: Wire) -> Self {
		Self { name, x, y }
	}
}

impl Gate for AssertEq {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		if w[self.x] != w[self.y] {
			w.flag_assertion_failed(format!(
				"{} failed: {:?} != {:?}",
				self.name, w[self.x], w[self.y]
			));
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
	pub name: String,
}

impl Assert0 {
	pub fn new(builder: &CircuitBuilder, name: String, a: Wire) -> Self {
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { name, a, all_1 }
	}
}

impl Gate for Assert0 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		// The constraint is: a & ALL_1 = 0, which means a must be 0
		if w[self.a] != Word::ZERO {
			w.flag_assertion_failed(format!("{} failed: {:?} != ZERO", self.name, self.a));
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

/// Conditional equality for a single byte inside the boundary word
/// Pattern: AND((v_a ^ v_b), m, 0) where m is mask (all-1 => enforce; 0 => no-op)
pub struct AssertEqCond {
	pub a: Wire,
	pub b: Wire,
	pub mask: Wire,
	pub name: String,
}

impl AssertEqCond {
	pub fn new(name: String, a: Wire, b: Wire, mask: Wire) -> Self {
		Self { a, b, mask, name }
	}
}

impl Gate for AssertEqCond {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let diff = w[self.a] ^ w[self.b];
		let masked_diff = diff & w[self.mask];
		if masked_diff != Word::ZERO {
			w.flag_assertion_failed(format!(
				"{} failed: {:?} != {:?}",
				self.name, w[self.a], w[self.b],
			));
		}
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let mask = circuit.witness_index(self.mask);

		// Constraint: AND((v_a ^ v_b), m, 0)
		cs.add_and_constraint(AndConstraint::plain_abc([a, b], [mask], []));
	}
}

/// Unsigned less-than test (a < b ? all-1 : all-0) using 2 AND constraints.
///
/// 1. AND((A ^ B) & (A ^ S), all-1, 0) - checks S = A - B
/// 2. AND((S sra 63) ^ F, all-1, 0) - binds F = sign(S)
pub struct IcmpUlt {
	pub a: Wire,
	pub b: Wire,
	pub result: Wire,
	pub s: Wire,
	pub all_1: Wire,
}

impl IcmpUlt {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let result = builder.add_witness();
		let s = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self {
			a,
			b,
			result,
			s,
			all_1,
		}
	}
}

impl Gate for IcmpUlt {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let a_val = w[self.a];
		let b_val = w[self.b];

		// S = A - B (two's complement subtraction)
		let s_val = a_val.wrapping_sub(b_val);
		w[self.s] = s_val;

		// F = sign(S): all-1 when A < B (S negative), all-0 when A >= B (S non-negative)
		let sign_bit = (s_val.as_u64() >> 63) & 1;
		w[self.result] = if sign_bit == 1 {
			Word::ALL_ONE
		} else {
			Word::ZERO
		};
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let result = circuit.witness_index(self.result);
		let s = circuit.witness_index(self.s);
		let all_1 = circuit.witness_index(self.all_1);

		// 1. AND((A ^ B) & (A ^ S), all-1, 0) - checks the subtraction (forces S = A - B)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(a), ShiftedValueIndex::plain(b)],
			[
				ShiftedValueIndex::plain(a),
				ShiftedValueIndex::plain(s),
				ShiftedValueIndex::plain(all_1),
			],
			[],
		));

		// 2. AND((S sra 63) ^ F, all-1, 0) - binds the result (F = sign(S))
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::sar(s, 63),
				ShiftedValueIndex::plain(result),
			],
			[ShiftedValueIndex::plain(all_1)],
			[],
		));
	}
}

/// 64-bit equality test that returns all-1 if equal, all-0 if not equal
/// Uses 1 AND constraint: AND(v_a ^ v_b, all-1, result ^ all-1)
pub struct IcmpEq {
	pub a: Wire,
	pub b: Wire,
	pub result: Wire,
	pub all_1: Wire,
}

impl IcmpEq {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let result = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self {
			a,
			b,
			result,
			all_1,
		}
	}
}

impl Gate for IcmpEq {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let a_val = w[self.a];
		let b_val = w[self.b];

		// Result is all-1 if equal, all-0 if not equal
		w[self.result] = if a_val == b_val {
			Word::ALL_ONE
		} else {
			Word::ZERO
		};
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let result = circuit.witness_index(self.result);
		let all_1 = circuit.witness_index(self.all_1);

		// AND(v_a ^ v_b, all-1, result ^ all-1)
		// When a == b: v_a ^ v_b = 0, so 0 & all-1 = 0 = result ^ all-1, meaning result = all-1
		// When a != b: v_a ^ v_b != 0, so constraint can only be satisfied if result = 0
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(a), ShiftedValueIndex::plain(b)],
			[ShiftedValueIndex::plain(all_1)],
			[
				ShiftedValueIndex::plain(result),
				ShiftedValueIndex::plain(all_1),
			],
		));
	}
}

/// Extract byte j from word using 2 AND constraints (j=0 is least significant byte).
///
/// 1. AND((word srl (8*j)) ^ b, 0xFF, 0) - forces low 8 bits of b to equal the byte
/// 2. AND(b, 0xFFFFFFFFFFFFFF00, 0) - forces high 56 bits of b to zero
pub struct ExtractByte {
	pub word: Wire,
	pub b: Wire,
	pub j: u32,
	pub mask_ff: Wire,
	pub mask_high56: Wire,
}

impl ExtractByte {
	pub fn new(builder: &CircuitBuilder, word: Wire, j: u32) -> Self {
		let b = builder.add_witness();
		let mask_ff = builder.add_constant(Word::from_u64(0xFF));
		let mask_high56 = builder.add_constant(Word::from_u64(0xFFFFFFFFFFFFFF00));
		Self {
			word,
			b,
			j,
			mask_ff,
			mask_high56,
		}
	}
}

impl Gate for ExtractByte {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let word_val = w[self.word];

		// Extract byte j from the word (shift right by 8*j bits and mask to get the byte)
		let byte_val = (word_val.as_u64() >> (8 * self.j)) & 0xFF;
		w[self.b] = Word::from_u64(byte_val);
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let word = circuit.witness_index(self.word);
		let b = circuit.witness_index(self.b);
		let mask_ff = circuit.witness_index(self.mask_ff);
		let mask_high56 = circuit.witness_index(self.mask_high56);

		// 1. AND((word srl (8*j)) ^ b, 0xFF, 0) - forces low 8 bits of b to equal the byte
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::srl(word, (8 * self.j) as usize),
				ShiftedValueIndex::plain(b),
			],
			[ShiftedValueIndex::plain(mask_ff)],
			[],
		));

		// 2. AND(b, 0xFFFFFFFFFFFFFF00, 0) - forces high 56 bits of b to zero
		cs.add_and_constraint(AndConstraint::plain_abc([b], [mask_high56], []));
	}
}

pub struct Shr {
	pub a: Wire,
	pub c: Wire,
	pub n: u32,
}

impl Shr {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let c = builder.add_witness();
		Self { a, c, n }
	}
}

impl Gate for Shr {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.a] >> self.n;
		w[self.c] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let c = circuit.witness_index(self.c);

		// SHR64 = srl(x, n)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::srl(a, self.n as usize)],
			[],
			[ShiftedValueIndex::plain(c)],
		));
	}
}

pub struct Shl {
	pub a: Wire,
	pub c: Wire,
	pub n: u32,
}

impl Shl {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let c = builder.add_witness();
		Self { a, c, n }
	}
}

impl Gate for Shl {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.a] << self.n;
		w[self.c] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let c = circuit.witness_index(self.c);

		// SHL = sll(x, n)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::sll(a, self.n as usize)],
			[],
			[ShiftedValueIndex::plain(c)],
		));
	}
}
