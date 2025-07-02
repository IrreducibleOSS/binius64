use crate::{
	compiler::{CircuitBuilder, Wire},
	word::Word,
};

/// Convert a boolean wire (0/1) to a mask of all ones (0xFFFF_FFFF) when the
/// value is one and zero otherwise.
pub fn bool_to_mask(b: &CircuitBuilder, x: Wire) -> Wire {
	// -x = (!x) + 1
	let not_x = b.bnot(x);
	let one = b.add_constant(Word::ONE);
	b.iadd_32(not_x, one)
}

/// Logical NOT for a boolean wire (0 or 1).
pub fn bool_not(b: &CircuitBuilder, x: Wire) -> Wire {
	let one = b.add_constant(Word::ONE);
	b.bxor(x, one)
}

/// Conditional equality check.
///
/// When `cond` is one, asserts that `x == y`.  When `cond` is zero, no
/// constraint is emitted on `x` and `y`.
pub fn assert_eq_cond(b: &CircuitBuilder, x: Wire, y: Wire, cond: Wire) {
	let diff = b.bxor(x, y);
	let mask = bool_to_mask(b, cond);
	let masked = b.band(diff, mask);
	let zero = b.add_constant(Word::ZERO);
	b.assert_eq(masked, zero);
}

/// Select between two wires depending on a boolean condition.
pub fn select(b: &CircuitBuilder, a: Wire, b0: Wire, cond: Wire) -> Wire {
	// b0 ^ (cond ? (a ^ b0) : 0)
	let diff = b.bxor(a, b0);
	let mask = bool_to_mask(b, cond);
	let masked = b.band(diff, mask);
	b.bxor(b0, masked)
}

/// Add a 32-bit constant to a word.
pub fn add_const(b: &CircuitBuilder, x: Wire, c: u32) -> Wire {
	let cst = b.add_constant(Word(c as u64));
	b.iadd_32(x, cst)
}

/// Compute x > const as a boolean wire (0/1).
pub fn gt_const(b: &CircuitBuilder, x: Wire, c: u32) -> Wire {
	// Compute x - (c + 1) and extract the sign bit.
	let k = (!(c + 1)).wrapping_add(1);
	let k = b.add_constant(Word(k as u64));
	let diff = b.iadd_32(x, k);
	let sign = b.shr_32(diff, 31);
	bool_not(b, sign)
}

/// Equality to a constant as boolean wire.
pub fn eq_const(b: &CircuitBuilder, x: Wire, c: u32) -> Wire {
	let ge = gt_const(b, x, c - 1);
	let gt = gt_const(b, x, c);
	let not_gt = bool_not(b, gt);
	b.band(ge, not_gt)
}

/// Shift left logically by `n` bits using repeated doubling.
pub fn shl_const(b: &CircuitBuilder, mut x: Wire, n: usize) -> Wire {
	for _ in 0..n {
		x = b.iadd_32(x, x);
	}
	x
}
