// Copyright 2025 Irreducible Inc.
use binius_frontend::CircuitBuilder;

use super::{addsub::compute_stack_adds, biguint::BigUint};

/// Multiply two arbitrary-sized `BigUint`s.
///
/// Computes `a * b` where both inputs are `BigUint`s. The result will have
/// `a.limbs.len() + b.limbs.len()` limbs to accommodate the full product
/// without overflow.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First operand `BigUint`
/// * `b` - Second operand `BigUint`
///
/// # Returns
/// Product `BigUint` with `a.limbs.len() + b.limbs.len()` limbs
pub fn mul(builder: &CircuitBuilder, a: &BigUint, b: &BigUint) -> BigUint {
	// Multiply argument's limbs pairwise.
	//
	// The accumulator has exactly a.limbs.len() + b.limbs.len() slots to hold
	// all partial products
	let mut accumulator = vec![vec![]; a.limbs.len() + b.limbs.len()];
	for (i, &ai) in a.limbs.iter().enumerate() {
		for (j, &bj) in b.limbs.iter().enumerate() {
			let (hi, lo) = builder.imul(ai, bj);
			let k = i + j;
			accumulator[k].push(lo);
			accumulator[k + 1].push(hi);
		}
	}
	compute_stack_adds(builder, &accumulator)
}

/// Square an arbitrary-sized `BigUint`.
///
/// Computes `a * a` using an optimized algorithm that takes advantage of the symmetry
/// in squaring (each cross-product appears twice). This is more efficient than
/// using general multiplication.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - The `BigUint` to be squared
///
/// # Returns
/// The square of `a` as a `BigUint` with `2 * a.limbs.len()` limbs
pub fn square(builder: &CircuitBuilder, a: &BigUint) -> BigUint {
	let mut accumulator = vec![vec![]; a.limbs.len() + a.limbs.len()];
	for (i, &ai) in a.limbs.iter().enumerate() {
		for (j, &aj) in a.limbs.iter().enumerate().skip(i) {
			let (hi, lo) = builder.imul(ai, aj);
			accumulator[i + j].push(lo);
			accumulator[i + j + 1].push(hi);
			if i != j {
				// Off-diagonal elements appear twice
				accumulator[i + j].push(lo);
				accumulator[i + j + 1].push(hi);
			}
		}
	}
	compute_stack_adds(builder, &accumulator)
}
