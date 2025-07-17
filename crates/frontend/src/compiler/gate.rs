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
	all_1: Wire,
}

impl Bxor {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let c = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { a, b, c, all_1 }
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
		let all_1 = circuit.witness_index(self.all_1);
		cs.add_and_constraint(AndConstraint::plain_abc([a, b], [all_1], [c]));
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

		let carry_bit = w[self.cin] >> 63;
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
		let (sum, carry) = w[self.a].iadd_cout_32(w[self.b]);

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

/// Unsigned less-than test returning a mask.
///
/// Returns `out_mask = all-1` if `x < y`, `all-0` otherwise.
///
/// # Algorithm
///
/// The gate computes `x < y` by checking if there's a borrow when computing `x - y`.
/// This is done by computing `¬x + y` and checking if it carries out (≥ 2^64).
///
/// 1. Compute carry bits `bout` from `¬x + y` using the constraint: `(¬x ⊕ bin) ∧ (y ⊕ bin) = bin ⊕
///    bout` where `bin = bout << 1`
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
pub struct IcmpUlt {
	pub x: Wire,
	pub y: Wire,
	pub out_mask: Wire,
	bout: Wire,
	all_1: Wire,
}

impl IcmpUlt {
	pub fn new(builder: &CircuitBuilder, x: Wire, y: Wire) -> Self {
		let z = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		let bout = builder.add_witness();

		Self {
			x,
			y,
			out_mask: z,
			bout,
			all_1,
		}
	}
}

impl Gate for IcmpUlt {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let x = w[self.x];
		let y = w[self.y];
		let all_1 = w[self.all_1];

		// Compute ¬x for the comparison
		let nx = all_1 ^ x;

		// Compute carry bits from ¬x + y using standard carry propagation
		// The MSB of bout indicates whether x < y:
		// - If ¬x + y ≥ 2^64 (carries out), then x < y
		// - If ¬x + y < 2^64 (no carry), then x ≥ y
		let (_, bout) = nx.iadd_cin_cout(y, Word::ZERO);
		w[self.bout] = bout;

		// Broadcast the MSB of bout to all bits to create the comparison mask
		let Word(bout_val) = bout;
		let bout_msb_broadcast = ((bout_val as i64) >> 63) as u64;
		let out_mask = Word(bout_msb_broadcast);

		w[self.out_mask] = out_mask;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let out_mask = circuit.witness_index(self.out_mask);
		let all_1 = circuit.witness_index(self.all_1);
		let bout = circuit.witness_index(self.bout);

		// Constraint 1: Borrow propagation
		//
		// (¬x ⊕ bin) ∧ (y ⊕ bin) = bin ⊕ bout
		let bin = ShiftedValueIndex::sll(bout, 1);
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::plain(x),
				ShiftedValueIndex::plain(all_1),
				bin,
			],
			[ShiftedValueIndex::plain(y), bin],
			[bin, ShiftedValueIndex::plain(bout)],
		));

		// Constraint 2: Mask generation
		//
		// out_mask = bout sar 63
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::sar(bout, 63)],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(out_mask)],
		));
	}
}

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
/// 2. Compute carry bits `cout` from `diff + all-1` using the constraint: `(x ⊕ y ⊕ cin) ∧ (all-1 ⊕
///    cin) = cin ⊕ cout` where `cin = cout << 1`
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
pub struct IcmpEq {
	pub x: Wire,
	pub y: Wire,
	pub out_mask: Wire,
	cout: Wire,
	all_1: Wire,
}

impl IcmpEq {
	pub fn new(builder: &CircuitBuilder, x: Wire, y: Wire) -> Self {
		let out_mask = builder.add_witness();
		let cout = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self {
			x,
			y,
			out_mask,
			cout,
			all_1,
		}
	}
}

impl Gate for IcmpEq {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let diff = w[self.x] ^ w[self.y];
		let (_, cout) = Word::ALL_ONE.iadd_cin_cout(diff, Word::ZERO);
		w[self.cout] = cout;
		w[self.out_mask] = !cout.sar(63);
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let out_mask = circuit.witness_index(self.out_mask);
		let cout = circuit.witness_index(self.cout);
		let all_1 = circuit.witness_index(self.all_1);

		let cin = ShiftedValueIndex::sll(cout, 1);

		// Constraint 1: Constrain carry-out.
		//
		// (x ⊕ y ⊕ cin) ∧ (all-1 ⊕ cin) = cin ⊕ cout
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::plain(x),
				ShiftedValueIndex::plain(y),
				cin,
			],
			[ShiftedValueIndex::plain(all_1), cin],
			[cin, ShiftedValueIndex::plain(cout)],
		));

		// Constraint 2: Broadcast the carry-out MSB to all bits.
		//
		// out_mask = ¬(cout sar 63)
		// out_mask = (cout sar 63) ⊕ all-1
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::sar(cout, 63),
				ShiftedValueIndex::plain(all_1),
			],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(out_mask)],
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
	all_1: Wire,
}

impl Shr {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let c = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { a, c, n, all_1 }
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
		let all_1 = circuit.witness_index(self.all_1);

		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::srl(a, self.n as usize)],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(c)],
		));
	}
}

pub struct Shl {
	pub a: Wire,
	pub c: Wire,
	pub n: u32,
	all_1: Wire,
}

impl Shl {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let c = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { a, c, n, all_1 }
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
		let all_1 = circuit.witness_index(self.all_1);

		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::sll(a, self.n as usize)],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(c)],
		));
	}
}
