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

/// 64-bit unsigned integer addition with carry propagation.
///
/// # Wires
///
/// - `a`, `b`: Input wires for the summands
/// - `cin` (carry-in): Input wire for the previous carry word. Only the MSB is used as the actual
///   carry bit
/// - `sum`: Output wire containing the resulting sum = a + b + carry_bit
/// - `cout` (carry-out): Output wire containing a carry word where each bit position indicates
///   whether a carry occurred at that position during the addition.
///
/// ## Carry-out Computation
///
/// The carry-out is computed as: `cout = (a & b) | ((a ^ b) & !sum)`
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
pub struct IaddCinCout {
	pub a: Wire,
	pub b: Wire,
	pub cin: Wire,
	pub sum: Wire,
	pub cout: Wire,
	all_1: Wire,
}

impl IaddCinCout {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire, cin: Wire) -> Self {
		let sum = builder.add_witness();
		let cout = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);

		Self {
			a,
			b,
			cin,
			sum,
			cout,
			all_1,
		}
	}
}

impl Gate for IaddCinCout {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let a = w[self.a];
		let b = w[self.b];

		// Extract carry-in bit from MSB of previous carry word
		let Word(cin) = w[self.cin];
		let carry_bit = cin >> 63;
		let (sum, carry_out) = a.iadd_cin_cout(b, carry_bit);

		w[self.sum] = sum;
		w[self.cout] = carry_out;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let sum = circuit.witness_index(self.sum);
		let cout = circuit.witness_index(self.cout);
		let all_ones = circuit.witness_index(self.all_1);
		let cin = circuit.witness_index(self.cin);

		let cout_sll_1 = ShiftedValueIndex::sll(cout, 1);
		// The carry bit
		let cin_msb = ShiftedValueIndex::srl(cin, 63);

		// (a XOR (cout << 1) XOR cin_msb) AND (b XOR (cout << 1) XOR cin_msb)
		// 		= cout XOR (cout << 1) XOR cin_msb
		let a_operands = vec![ShiftedValueIndex::plain(a), cout_sll_1, cin_msb];
		let b_operands = vec![ShiftedValueIndex::plain(b), cout_sll_1, cin_msb];
		let c_operands = vec![ShiftedValueIndex::plain(cout), cout_sll_1, cin_msb];

		// a XOR b XOR (cout << 1) XOR cin_msb
		let sum_operands = vec![
			ShiftedValueIndex::plain(a),
			ShiftedValueIndex::plain(b),
			ShiftedValueIndex::sll(cout, 1),
			cin_msb,
		];

		// carry propagation constraint
		cs.add_and_constraint(AndConstraint::abc(a_operands, b_operands, c_operands));

		// sum equality constraint
		cs.add_and_constraint(AndConstraint::abc(
			sum_operands,
			[ShiftedValueIndex::plain(all_ones)],
			[ShiftedValueIndex::plain(sum)],
		));
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
	all_1: Wire,
}

impl AssertEq {
	pub fn new(builder: &CircuitBuilder, name: String, x: Wire, y: Wire) -> Self {
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { name, x, y, all_1 }
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
		let all_1 = circuit.witness_index(self.all_1);
		cs.add_and_constraint(AndConstraint::plain_abc([x, y], [all_1], []));
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

/// Assert that bitwise AND of wire with constant equals zero.
/// Pattern: AND(a, constant, 0) which constrains a & constant = 0
pub struct AssertBand0 {
	pub a: Wire,
	pub constant: Wire,
	pub name: String,
}

impl AssertBand0 {
	pub fn new(builder: &CircuitBuilder, name: String, a: Wire, constant: Word) -> Self {
		let constant = builder.add_constant(constant);
		Self { name, a, constant }
	}
}

impl Gate for AssertBand0 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.a] & w[self.constant];
		if result != Word::ZERO {
			w.flag_assertion_failed(format!(
				"{} failed: {:?} & {:?} = {:?} != ZERO",
				self.name, w[self.a], w[self.constant], result
			));
		}
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let constant = circuit.witness_index(self.constant);

		// Constraint: AND(a, constant, 0) => a & constant = 0
		cs.add_and_constraint(AndConstraint::plain_abc([a], [constant], []));
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

/// Unsigned less-than test (a < b ? all-1 : all-0) using 4 AND constraints.
///
/// Implements a < b by computing a - b = a + (~b) + 1 and checking the carry out.
/// If there's no carry out from MSB (borrow occurred), then a < b.
pub struct IcmpUlt {
	pub a: Wire,
	pub b: Wire,
	pub result: Wire,
	not_b: Wire,
	cin: Wire,
	diff: Wire,
	cout: Wire,
	all_1: Wire,
}

impl IcmpUlt {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let result = builder.add_witness();
		let not_b = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		// 1 in MSB for carry-in
		let cin = builder.add_constant(Word::from_u64(1u64 << 63));
		// internal carry-bits in diff calculation
		let cout = builder.add_witness();
		// holds a - b
		let diff = builder.add_witness();

		Self {
			a,
			b,
			result,
			not_b,
			cin,
			diff,
			cout,
			all_1,
		}
	}
}

impl Gate for IcmpUlt {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let a = w[self.a];
		let b = w[self.b];

		let not_b = w[self.all_1] ^ b;
		w[self.not_b] = not_b;

		// extract the incoming carry-in (MSB of cin)
		let cin_bit = w[self.cin].as_u64() >> 63;

		// compute a - b = a + (~b) + 1
		let (diff, carry_out) = a.iadd_cin_cout(not_b, cin_bit);
		w[self.diff] = diff;
		w[self.cout] = carry_out;

		// For unsigned comparison a < b:
		// We compute a - b = a + (~b) + 1
		// If there's a carry out from MSB (carry[63] = 1), then a >= b (no borrow)
		// If there's no carry out from MSB (carry[63] = 0), then a < b (borrow occurred)
		//
		// Extract the carry_out bit
		let carry_out_bit = carry_out.as_u64() >> 63;
		// Negate the carry_out bit to get the borrow (1 if borrow occurred, 0 if
		// borrow did not occur)
		let borrow = carry_out_bit ^ 1;
		// Result is zero if bottow = 0 and all-1 if borrow = 1
		w[self.result] = Word::from_u64(borrow.wrapping_neg());
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let result = circuit.witness_index(self.result);
		let not_b = circuit.witness_index(self.not_b);
		let all_1 = circuit.witness_index(self.all_1);
		let diff = circuit.witness_index(self.diff);
		let cout = circuit.witness_index(self.cout);
		let cin = circuit.witness_index(self.cin);

		// Constraint 1: not_b = b ^ all_1
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(b), ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(not_b)],
		));

		// Shift cout left by 1 to align bits with cin
		let cout_sll_1 = ShiftedValueIndex::sll(cout, 1);
		// The carry bit
		let cin_msb = ShiftedValueIndex::srl(cin, 63);

		// Constraint 2: Carry propagation constraint
		// (a XOR (cout << 1) XOR cin_msb) AND (not_b XOR (cout << 1) XOR cin_msb)
		// 		= cout XOR (cout << 1) XOR cin_msb
		let a_operands = vec![ShiftedValueIndex::plain(a), cout_sll_1, cin_msb];
		let b_operands = vec![ShiftedValueIndex::plain(not_b), cout_sll_1, cin_msb];
		let c_operands = vec![ShiftedValueIndex::plain(cout), cout_sll_1, cin_msb];

		cs.add_and_constraint(AndConstraint::abc(a_operands, b_operands, c_operands));

		// Constraint 3: Diff constraint
		let sum_operands = vec![
			ShiftedValueIndex::plain(a),
			ShiftedValueIndex::plain(not_b),
			ShiftedValueIndex::sll(cout, 1),
			cin_msb,
		];

		// (a XOR not_b XOR (cout << 1) XOR cin_msb) AND all_1 = diff
		cs.add_and_constraint(AndConstraint::abc(
			sum_operands,
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(diff)],
		));

		// Constraint 4: Map carry MSB to result
		// For unsigned less-than:
		// - If carry[63] = 0 (no carry out, i.e., borrow), then result = all-1 (a < b)
		// - If carry[63] = 1 (carry out, no borrow), then result = 0 (a >= b)
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::sar(cout, 63),
				ShiftedValueIndex::plain(all_1),
			],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(result)],
		));
	}
}

/// 64-bit equality test that returns all-1 if equal, all-0 if not equal.
///
/// Uses 8 AND constraints with a bit-folding approach to ensure soundness.
///
/// # Algorithm
///
/// The gate computes:
/// 1. `v2 = ~(a ^ b)` (all-1 if equal, has zeros if not equal)
/// 2. Folds all 64 bits down to a single bit using 6 AND operations
/// 3. Broadcasts the single bit result to all 64 bits
///
/// # Constraints
///
/// The gate generates 8 AND constraints:
///
/// 1. Compute `v2 = ~(a ^ b)`
/// 2. Fold bits: v3 = v2 & (v2 >> 32), v4 = v3 & (v3 >> 16), etc.
/// 3. Broadcast final bit to all 64 bits
pub struct IcmpEq {
	pub a: Wire,
	pub b: Wire,
	pub result: Wire,
	v2: Wire, // ~(a ^ b)
	v3: Wire, // fold 32
	v4: Wire, // fold 16
	v5: Wire, // fold 8
	v6: Wire, // fold 4
	v7: Wire, // fold 2
	v8: Wire, // fold 1 - single bit result
	all_1: Wire,
}

impl IcmpEq {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let result = builder.add_witness();
		let v2 = builder.add_witness();
		let v3 = builder.add_witness();
		let v4 = builder.add_witness();
		let v5 = builder.add_witness();
		let v6 = builder.add_witness();
		let v7 = builder.add_witness();
		let v8 = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);

		Self {
			a,
			b,
			result,
			v2,
			v3,
			v4,
			v5,
			v6,
			v7,
			v8,
			all_1,
		}
	}
}

impl Gate for IcmpEq {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let a_val = w[self.a];
		let b_val = w[self.b];

		// Step 1: v2 = ~(a ^ b)
		// If a == b, then a ^ b = 0, so v2 = ~0 = all-1
		// If a != b, then a ^ b has some 1 bits, so v2 has some 0 bits
		let v2_val = (a_val ^ b_val) ^ Word::ALL_ONE;
		w[self.v2] = v2_val;

		// Steps 2-7: Fold all 64 bits down to a single bit
		// If v2 = all-1, then all folded values will be all-1, and v8 = 1
		// If v2 has any 0 bit, the folding will propagate it, and v8 = 0

		// v3 = v2 & (v2 >> 32)
		let v3_val = v2_val & (v2_val >> 32);
		w[self.v3] = v3_val;

		// v4 = v3 & (v3 >> 16)
		let v4_val = v3_val & (v3_val >> 16);
		w[self.v4] = v4_val;

		// v5 = v4 & (v4 >> 8)
		let v5_val = v4_val & (v4_val >> 8);
		w[self.v5] = v5_val;

		// v6 = v5 & (v5 >> 4)
		let v6_val = v5_val & (v5_val >> 4);
		w[self.v6] = v6_val;

		// v7 = v6 & (v6 >> 2)
		let v7_val = v6_val & (v6_val >> 2);
		w[self.v7] = v7_val;

		// v8 = v7 & (v7 >> 1)
		// At this point, v8 will have its LSB = 1 if all bits were 1, else 0
		let v8_val = v7_val & (v7_val >> 1);
		w[self.v8] = v8_val;

		// Step 8: Broadcast v8's LSB to all 64 bits
		// Extract the LSB and replicate it to all positions
		let lsb = v8_val.as_u64() & 1;
		w[self.result] = Word::from_u64(lsb.wrapping_neg());
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let a = circuit.witness_index(self.a);
		let b = circuit.witness_index(self.b);
		let result = circuit.witness_index(self.result);
		let v2 = circuit.witness_index(self.v2);
		let v3 = circuit.witness_index(self.v3);
		let v4 = circuit.witness_index(self.v4);
		let v5 = circuit.witness_index(self.v5);
		let v6 = circuit.witness_index(self.v6);
		let v7 = circuit.witness_index(self.v7);
		let v8 = circuit.witness_index(self.v8);
		let all_1 = circuit.witness_index(self.all_1);

		// Constraint 1: v2 = ~(a ^ b)
		// ((a ^ b) ^ all_1) & all_1 = v2
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::plain(a),
				ShiftedValueIndex::plain(b),
				ShiftedValueIndex::plain(all_1),
			],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(v2)],
		));

		// Constraint 2: v3 = v2 & (v2 >> 32)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(v2)],
			[ShiftedValueIndex::srl(v2, 32)],
			[ShiftedValueIndex::plain(v3)],
		));

		// Constraint 3: v4 = v3 & (v3 >> 16)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(v3)],
			[ShiftedValueIndex::srl(v3, 16)],
			[ShiftedValueIndex::plain(v4)],
		));

		// Constraint 4: v5 = v4 & (v4 >> 8)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(v4)],
			[ShiftedValueIndex::srl(v4, 8)],
			[ShiftedValueIndex::plain(v5)],
		));

		// Constraint 5: v6 = v5 & (v5 >> 4)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(v5)],
			[ShiftedValueIndex::srl(v5, 4)],
			[ShiftedValueIndex::plain(v6)],
		));

		// Constraint 6: v7 = v6 & (v6 >> 2)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(v6)],
			[ShiftedValueIndex::srl(v6, 2)],
			[ShiftedValueIndex::plain(v7)],
		));

		// Constraint 7: v8 = v7 & (v7 >> 1)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(v7)],
			[ShiftedValueIndex::srl(v7, 1)],
			[ShiftedValueIndex::plain(v8)],
		));

		// Constraint 8: Broadcast v8's LSB to all 64 bits
		// v8 ^ (v8 << 1) ^ (v8 << 2) ^ ... ^ (v8 << 63) & all_1 = result
		let mut broadcast_operands = vec![ShiftedValueIndex::plain(v8)];
		for i in 1..64 {
			broadcast_operands.push(ShiftedValueIndex::sll(v8, i));
		}

		cs.add_and_constraint(AndConstraint::abc(
			broadcast_operands,
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(result)],
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
