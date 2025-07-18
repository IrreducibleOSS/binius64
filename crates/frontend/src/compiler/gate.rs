use super::{Circuit, CircuitBuilder, Wire, WitnessFiller};
use crate::{
	constraint_system::{AndConstraint, ConstraintSystem, MulConstraint, ShiftedValueIndex},
	word::Word,
};

pub trait Gate {
	fn populate_wire_witness(&self, w: &mut WitnessFiller);
	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem);
}

/// Bitwise AND operation.
///
/// Returns `z = x & y`.
///
/// # Algorithm
///
/// Computes the bitwise AND of two 64-bit words using a single AND constraint.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ y = z`
pub struct Band {
	pub x: Wire,
	pub y: Wire,
	pub z: Wire,
}

impl Band {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let z = builder.add_witness();
		Self { x: a, y: b, z }
	}
}

impl Gate for Band {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		w[self.z] = w[self.x] & w[self.y];
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let z = circuit.witness_index(self.z);

		// Constraint: Bitwise AND
		//
		// x ∧ y = z
		cs.add_and_constraint(AndConstraint::plain_abc([x], [y], [z]));
	}
}

/// Bitwise XOR operation.
///
/// Returns `z = x ^ y`.
///
/// # Algorithm
///
/// Computes the bitwise XOR using the identity: `x ^ y = ¬(x ∧ y)`.
/// This is implemented as `(x ⊕ y) ∧ all-1 = z`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x ⊕ y) ∧ all-1 = z`
pub struct Bxor {
	pub x: Wire,
	pub y: Wire,
	pub z: Wire,
	all_1: Wire,
}

impl Bxor {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let z = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self {
			x: a,
			y: b,
			z,
			all_1,
		}
	}
}

impl Gate for Bxor {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		w[self.z] = w[self.x] ^ w[self.y];
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let z = circuit.witness_index(self.z);
		let all_1 = circuit.witness_index(self.all_1);

		// Constraint: Bitwise XOR
		//
		// (x ⊕ y) ∧ all-1 = z
		cs.add_and_constraint(AndConstraint::plain_abc([x, y], [all_1], [z]));
	}
}

/// Bitwise OR operation.
///
/// Returns `z = x | y`.
///
/// # Algorithm
///
/// Computes the bitwise OR using De Morgan's law: `x | y = ¬(¬x ∧ ¬y)`.
/// This is implemented as `x ∧ y = (x ⊕ y ⊕ z)`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ y = x ⊕ y ⊕ z`
pub struct Bor {
	pub x: Wire,
	pub y: Wire,
	pub z: Wire,
}

impl Bor {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let z = builder.add_witness();
		Self { x: a, y: b, z }
	}
}

impl Gate for Bor {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		w[self.z] = w[self.x] | w[self.y];
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let z = circuit.witness_index(self.z);

		// Constraint: Bitwise OR
		//
		// x ∧ y = x ⊕ y ⊕ z
		cs.add_and_constraint(AndConstraint::plain_abc([x], [y], [x, y, z]));
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

		let a_operands = vec![ShiftedValueIndex::plain(a), cout_sll_1, cin_msb];
		let b_operands = vec![ShiftedValueIndex::plain(b), cout_sll_1, cin_msb];
		let c_operands = vec![ShiftedValueIndex::plain(cout), cout_sll_1, cin_msb];

		let sum_operands = vec![
			ShiftedValueIndex::plain(a),
			ShiftedValueIndex::plain(b),
			ShiftedValueIndex::sll(cout, 1),
			cin_msb,
		];

		// Constraint 1: Carry propagation
		//
		// (a ⊕ (cout << 1) ⊕ cin_msb) ∧ (b ⊕ (cout << 1) ⊕ cin_msb) = cout ⊕ (cout << 1) ⊕ cin_msb
		cs.add_and_constraint(AndConstraint::abc(a_operands, b_operands, c_operands));

		// Constraint 2: Sum equality
		//
		// (a ⊕ b ⊕ (cout << 1) ⊕ cin_msb) ∧ all-1 = sum
		cs.add_and_constraint(AndConstraint::abc(
			sum_operands,
			[ShiftedValueIndex::plain(all_ones)],
			[ShiftedValueIndex::plain(sum)],
		));
	}
}

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
pub struct Iadd32 {
	pub x: Wire,
	pub y: Wire,
	pub z: Wire,
	pub cout: Wire,
	pub mask32: Wire,
}

impl Iadd32 {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let z = builder.add_witness();
		let cout = builder.add_witness();
		let mask32 = builder.add_constant(Word::MASK_32);
		Self {
			x: a,
			y: b,
			z,
			cout,
			mask32,
		}
	}
}

impl Gate for Iadd32 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let (sum, carry) = w[self.x].iadd_cout_32(w[self.y]);

		w[self.z] = sum;
		w[self.cout] = carry;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let z = circuit.witness_index(self.z);
		let cout = circuit.witness_index(self.cout);
		let mask32 = circuit.witness_index(self.mask32);

		// Constraint 1: Carry propagation
		//
		// (x ⊕ (cout << 1)) ∧ (y ⊕ (cout << 1)) = cout ⊕ (cout << 1)
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::plain(x), ShiftedValueIndex::sll(cout, 1)],
			[ShiftedValueIndex::plain(y), ShiftedValueIndex::sll(cout, 1)],
			[
				ShiftedValueIndex::plain(cout),
				ShiftedValueIndex::sll(cout, 1),
			],
		));

		// Constraint 2: Result masking
		//
		// (x ⊕ y ⊕ (cout << 1)) ∧ MASK_32 = z
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::plain(x),
				ShiftedValueIndex::plain(y),
				ShiftedValueIndex::sll(cout, 1),
			],
			[ShiftedValueIndex::plain(mask32)],
			[ShiftedValueIndex::plain(z)],
		));
	}
}

/// 32-bit logical right shift.
///
/// Returns `z = (x >> n) & MASK_32`.
///
/// # Algorithm
///
/// Shifts the input right by `n` bits and masks to 32 bits.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x >> n) ∧ MASK_32 = z`
pub struct Shr32 {
	pub x: Wire,
	pub z: Wire,
	pub mask32: Wire,
	pub n: u32,
}

impl Shr32 {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let z = builder.add_witness();
		let mask32 = builder.add_constant(Word::MASK_32);
		Self { x: a, z, mask32, n }
	}
}

impl Gate for Shr32 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.x].shr_32(self.n);
		w[self.z] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let z = circuit.witness_index(self.z);
		let mask32 = circuit.witness_index(self.mask32);

		// Constraint: Shift right with masking
		//
		// (x >> n) ∧ MASK_32 = z
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::srl(x, self.n as usize)],
			[ShiftedValueIndex::plain(mask32)],
			[ShiftedValueIndex::plain(z)],
		));
	}
}

/// 32-bit rotate right.
///
/// Returns `z = ((x >> n) | (x << (32-n))) & MASK_32`.
///
/// # Algorithm
///
/// Rotates a 32-bit value right by `n` positions:
/// 1. Shift right by n: `t1 = x >> n` (bits n-31 move to positions 0-(31-n))
/// 2. Shift left by 32-n: `t2 = x << (32-n)` (bits 0-(n-1) move to positions (32-n)-31)
/// 3. Combine with XOR: Since the shifted ranges don't overlap, `t1 | t2 = t1 ^ t2`
/// 4. Mask to 32 bits: `z = (t1 ^ t2) & MASK_32`
///
/// The non-overlapping property is crucial: right-shifted bits occupy positions 0-(31-n),
/// while left-shifted bits occupy positions (32-n)-31, with no overlap.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `((x >> n) ⊕ (x << (32-n))) ∧ MASK_32 = z`
pub struct Rotr32 {
	pub x: Wire,
	pub z: Wire,
	pub mask32: Wire,
	pub n: u32,
}

impl Rotr32 {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let z = builder.add_witness();
		let mask32 = builder.add_constant(Word::MASK_32);
		Self { x: a, z, mask32, n }
	}
}

impl Gate for Rotr32 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.x].rotr_32(self.n);
		w[self.z] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let z = circuit.witness_index(self.z);
		let mask32 = circuit.witness_index(self.mask32);

		// Constraint: Rotate right
		//
		// ((x >> n) ⊕ (x << (32-n))) ∧ MASK_32 = z
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::srl(x, self.n as usize),
				ShiftedValueIndex::sll(x, (32 - self.n) as usize),
			],
			[ShiftedValueIndex::plain(mask32)],
			[ShiftedValueIndex::plain(z)],
		));
	}
}

/// Equality assertion.
///
/// Enforces `x = y` using an AND constraint.
///
/// # Algorithm
///
/// Uses the property that `x = y` iff `x ^ y = 0`.
/// This is enforced as `(x ⊕ y) ∧ all-1 = 0`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x ⊕ y) ∧ all-1 = 0`
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

		// Constraint: Equality assertion
		//
		// (x ⊕ y) ∧ all-1 = 0
		cs.add_and_constraint(AndConstraint::plain_abc([x, y], [all_1], []));
	}
}

/// Assert that a wire equals zero.
///
/// Enforces `x = 0` using an AND constraint.
///
/// # Algorithm
///
/// Uses the constraint `x ∧ all-1 = 0`, which forces `x = 0`.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ all-1 = 0`
pub struct Assert0 {
	pub x: Wire,
	pub all_1: Wire,
	pub name: String,
}

impl Assert0 {
	pub fn new(builder: &CircuitBuilder, name: String, a: Wire) -> Self {
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { name, x: a, all_1 }
	}
}

impl Gate for Assert0 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		// The constraint is: x & ALL_1 = 0, which means x must be 0
		if w[self.x] != Word::ZERO {
			w.flag_assertion_failed(format!("{} failed: {:?} != ZERO", self.name, self.x));
		}
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let all_1 = circuit.witness_index(self.all_1);

		// Constraint: Assert zero
		//
		// x ∧ all-1 = 0
		cs.add_and_constraint(AndConstraint::plain_abc([x], [all_1], []));
	}
}

/// Assert that bitwise AND equals zero.
///
/// Enforces `x & constant = 0`.
///
/// # Algorithm
///
/// Directly constrains that the bitwise AND of `x` with a constant equals zero.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `x ∧ constant = 0`
pub struct AssertBand0 {
	pub x: Wire,
	pub constant: Wire,
	pub name: String,
}

impl AssertBand0 {
	pub fn new(builder: &CircuitBuilder, name: String, a: Wire, constant: Word) -> Self {
		let constant = builder.add_constant(constant);
		Self {
			name,
			x: a,
			constant,
		}
	}
}

impl Gate for AssertBand0 {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.x] & w[self.constant];
		if result != Word::ZERO {
			w.flag_assertion_failed(format!(
				"{} failed: {:?} & {:?} = {:?} != ZERO",
				self.name, w[self.x], w[self.constant], result
			));
		}
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let constant = circuit.witness_index(self.constant);

		// Constraint: Assert bitwise AND equals zero
		//
		// x ∧ constant = 0
		cs.add_and_constraint(AndConstraint::plain_abc([x], [constant], []));
	}
}

/// Imul gate implements 64-bit × 64-bit → 128-bit unsigned multiplication.
/// Uses the MulConstraint: X * Y = (HI << 64) | LO
pub struct Imul {
	pub x: Wire,
	pub y: Wire,
	pub hi: Wire,
	pub lo: Wire,
}

impl Imul {
	pub fn new(builder: &CircuitBuilder, a: Wire, b: Wire) -> Self {
		let hi = builder.add_witness();
		let lo = builder.add_witness();
		Self { x: a, y: b, hi, lo }
	}
}

impl Gate for Imul {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let (hi, lo) = w[self.x].imul(w[self.y]);
		w[self.hi] = hi;
		w[self.lo] = lo;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let hi = circuit.witness_index(self.hi);
		let lo = circuit.witness_index(self.lo);

		// Create MulConstraint: X * Y = (HI << 64) | LO
		let mul_constraint = MulConstraint {
			a: vec![ShiftedValueIndex::plain(x)],
			b: vec![ShiftedValueIndex::plain(y)],
			hi: vec![ShiftedValueIndex::plain(hi)],
			lo: vec![ShiftedValueIndex::plain(lo)],
		};

		cs.add_mul_constraint(mul_constraint);
	}
}

/// Conditional equality assertion.
///
/// Enforces `x = y` when `mask = all-1`, no constraint when `mask = 0`.
///
/// # Algorithm
///
/// Uses a mask to conditionally enforce equality: `(x ^ y) & mask = 0`.
/// When mask is all-1, this enforces `x = y`. When mask is 0, the constraint is satisfied
/// trivially.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x ⊕ y) ∧ mask = 0`
pub struct AssertEqCond {
	pub x: Wire,
	pub y: Wire,
	pub mask: Wire,
	pub name: String,
}

impl AssertEqCond {
	pub fn new(name: String, a: Wire, b: Wire, mask: Wire) -> Self {
		Self {
			x: a,
			y: b,
			mask,
			name,
		}
	}
}

impl Gate for AssertEqCond {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let diff = w[self.x] ^ w[self.y];
		let masked_diff = diff & w[self.mask];
		if masked_diff != Word::ZERO {
			w.flag_assertion_failed(format!(
				"{} failed: {:?} != {:?}",
				self.name, w[self.x], w[self.y],
			));
		}
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let y = circuit.witness_index(self.y);
		let mask = circuit.witness_index(self.mask);

		// Constraint: Conditional equality
		//
		// (x ⊕ y) ∧ mask = 0
		cs.add_and_constraint(AndConstraint::plain_abc([x, y], [mask], []));
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

/// Extract byte from word (little-endian).
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
pub struct ExtractByte {
	pub word: Wire,
	pub z: Wire,
	pub j: u32,
	pub mask_ff: Wire,
	pub mask_high56: Wire,
}

impl ExtractByte {
	pub fn new(builder: &CircuitBuilder, word: Wire, j: u32) -> Self {
		let z = builder.add_witness();
		let mask_ff = builder.add_constant(Word::from_u64(0xFF));
		let mask_high56 = builder.add_constant(Word::from_u64(0xFFFFFFFFFFFFFF00));
		Self {
			word,
			z,
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
		w[self.z] = Word::from_u64(byte_val);
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let word = circuit.witness_index(self.word);
		let z = circuit.witness_index(self.z);
		let mask_ff = circuit.witness_index(self.mask_ff);
		let mask_high56 = circuit.witness_index(self.mask_high56);

		// Constraint 1: Low byte extraction
		//
		// ((word >> (8*j)) ⊕ z) ∧ 0xFF = 0
		cs.add_and_constraint(AndConstraint::abc(
			[
				ShiftedValueIndex::srl(word, (8 * self.j) as usize),
				ShiftedValueIndex::plain(z),
			],
			[ShiftedValueIndex::plain(mask_ff)],
			[],
		));

		// Constraint 2: High bits zeroing
		//
		// z ∧ 0xFFFFFFFFFFFFFF00 = 0
		cs.add_and_constraint(AndConstraint::plain_abc([z], [mask_high56], []));
	}
}

/// Logical right shift.
///
/// Returns `z = x >> n`.
///
/// # Algorithm
///
/// Performs a logical right shift by `n` bits. The constraint system allows
/// referencing shifted versions of values directly without additional gates.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x >> n) ∧ all-1 = z`
pub struct Shr {
	pub x: Wire,
	pub z: Wire,
	pub n: u32,
	all_1: Wire,
}

impl Shr {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let z = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { x: a, z, n, all_1 }
	}
}

impl Gate for Shr {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.x] >> self.n;
		w[self.z] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let z = circuit.witness_index(self.z);
		let all_1 = circuit.witness_index(self.all_1);

		// Constraint: Logical right shift
		//
		// (x >> n) ∧ all-1 = z
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::srl(x, self.n as usize)],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(z)],
		));
	}
}

/// Logical left shift.
///
/// Returns `z = x << n`.
///
/// # Algorithm
///
/// Performs a logical left shift by `n` bits. The constraint system allows
/// referencing shifted versions of values directly without additional gates.
///
/// # Constraints
///
/// The gate generates 1 AND constraint:
/// - `(x << n) ∧ all-1 = z`
pub struct Shl {
	pub x: Wire,
	pub z: Wire,
	pub n: u32,
	all_1: Wire,
}

impl Shl {
	pub fn new(builder: &CircuitBuilder, a: Wire, n: u32) -> Self {
		let z = builder.add_witness();
		let all_1 = builder.add_constant(Word::ALL_ONE);
		Self { x: a, z, n, all_1 }
	}
}

impl Gate for Shl {
	fn populate_wire_witness(&self, w: &mut WitnessFiller) {
		let result = w[self.x] << self.n;
		w[self.z] = result;
	}

	fn constrain(&self, circuit: &Circuit, cs: &mut ConstraintSystem) {
		let x = circuit.witness_index(self.x);
		let z = circuit.witness_index(self.z);
		let all_1 = circuit.witness_index(self.all_1);

		// Constraint: Logical left shift
		//
		// (x << n) ∧ all-1 = z
		cs.add_and_constraint(AndConstraint::abc(
			[ShiftedValueIndex::sll(x, self.n as usize)],
			[ShiftedValueIndex::plain(all_1)],
			[ShiftedValueIndex::plain(z)],
		));
	}
}
