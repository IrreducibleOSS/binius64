//! Arbitrary-precision bignum arithmetic for circuits.
//!
//! This module provides operations on big integers represented as vectors of `Wire` elements,
//! where each `Wire` represents a 64-bit limb. The representation uses little-endian ordering,
//! meaning the least significant limb is at index 0.
//!
//! # BigNum Representation
//!
//! A bignum is represented as `&[Wire]` or `Vec<Wire>` where:
//! - Each `Wire` holds a 64-bit unsigned integer value (a "limb")
//! - Limbs are stored in little-endian order (index 0 = least significant)
//! - The number of limbs determines the maximum value that can be represented
//!
//! # Size Conventions
//!
//! - Addition: Input size n produces output size n (with overflow checks)
//! - Multiplication: Input sizes n and m produce output size n + m
//! - Squaring: Input size n produces output size 2n
//! - Comparison: Inputs must be the same size

use num_bigint::BigUint;

#[cfg(test)]
mod tests;

use crate::{
	compiler::{CircuitBuilder, Wire, WitnessFiller},
	word::Word,
};

/// Multiply two arbitrary-sized bignums.
///
/// Computes `a * b` where both inputs are big integers represented as slices of 64-bit limbs.
/// The result will have `a.len() + b.len()` limbs to accommodate the full product without overflow.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First multiplicand as little-endian limbs
/// * `b` - Second multiplicand as little-endian limbs
///
/// # Returns
/// Product as a vector of limbs with length `a.len() + b.len()`
pub fn mul(builder: &CircuitBuilder, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
	// Multiply argument's limbs pairwise
	// The accumulator has exactly a.len() + b.len() slots to hold all partial products
	let mut accumulator = vec![vec![]; a.len() + b.len()];
	for (i, &ai) in a.iter().enumerate() {
		for (j, &bj) in b.iter().enumerate() {
			let (hi, lo) = builder.imul(ai, bj);
			let k = i + j;
			accumulator[k].push(lo);
			accumulator[k + 1].push(hi);
		}
	}
	compute_stack_adds(builder, &accumulator)
}

/// Square an arbitrary-sized bignum.
///
/// Computes `a * a` using an optimized algorithm that takes advantage of the symmetry
/// in squaring (each cross-product appears twice). This is more efficient than
/// using general multiplication.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - Input bignum as little-endian limbs
///
/// # Returns
/// Square as a vector of limbs with length `2 × a.len()`
pub fn square(builder: &CircuitBuilder, a: &[Wire]) -> Vec<Wire> {
	let mut accumulator = vec![vec![]; a.len() + a.len()];
	for (i, &ai) in a.iter().enumerate() {
		for (j, &aj) in a.iter().enumerate().skip(i) {
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

/// Compare two arbitrary-sized bignums for equality.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First bignum as little-endian limbs
/// * `b` - Second bignum as little-endian limbs (must have same length as `a`)
///
/// # Returns
/// A `Wire` that evaluates to:
/// - `0xFFFFFFFFFFFFFFFF` (all ones) if `a == b`
/// - `0x0000000000000000` (all zeros) if `a != b`
///
/// # Panics
/// Panics if `a` and `b` have different lengths.
pub fn compare(builder: &CircuitBuilder, a: &[Wire], b: &[Wire]) -> Wire {
	assert_eq!(a.len(), b.len(), "compare: inputs must have the same length");

	if a.is_empty() {
		return builder.add_constant(Word::ALL_ONE);
	}

	// NB: An alternative approach, to reduce the number of icmp_eq gates used
	// is:
	//
	//  1. XOR each limb pair
	//  2. OR all the results together
	//  3. compare the result of 2 with zero
	//
	// However when I treid this I got constraint verification errors in the
	// tests.

	// For each limb pair, compute equality (all 1s if equal, all 0s if not)
	let eq_results: Vec<Wire> = a
		.iter()
		.zip(b.iter())
		.map(|(&x, &y)| builder.icmp_eq(x, y))
		.collect();

	// AND all equality results together
	eq_results
		.into_iter()
		.reduce(|acc, x| builder.band(acc, x))
		.unwrap()
}

/// Add two arbitrary-sized bignums with carry propagation.
///
/// Computes `a + b` with proper carry handling between limbs. The result
/// has the same number of limbs as the inputs. Overflow beyond the most
/// significant limb is checked and must be zero.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First addend as little-endian limbs
/// * `b` - Second addend as little-endian limbs (must have same length as `a`)
///
/// # Returns
/// Sum as a vector of limbs with same length as inputs
///
/// # Panics
/// - Panics if `a` and `b` have different lengths
pub fn add(builder: &CircuitBuilder, a: &[Wire], b: &[Wire]) -> Vec<Wire> {
	assert_eq!(a.len(), b.len(), "add: inputs must have the same length");

	let mut accumulator = vec![vec![]; a.len()];
	for i in 0..a.len() {
		accumulator[i].push(a[i]);
		accumulator[i].push(b[i]);
	}
	compute_stack_adds(builder, &accumulator)
}

/// Computes multi-operand addition with carry propagation across limb positions.
///
/// This function is the core of bignum arithmetic, handling the addition of multiple
/// values at each limb position with proper carry propagation to higher limbs.
/// It's used by other bignum operations to resolve partial products and sums.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `limb_stacks` - Array where `limb_stacks[i]` contains all values to be added at limb position
///   `i`.
///
/// # Constraints
/// - Final carries must be zero (enforced by circuit constraints) This ensures the result fits in
///   the allocated number of limbs without overflow
fn compute_stack_adds(builder: &CircuitBuilder, limb_stacks: &[Vec<Wire>]) -> Vec<Wire> {
	let mut sums = Vec::new();
	let mut carries = Vec::new();
	let zero = builder.add_constant(Word::ZERO);

	for limb_stack in limb_stacks {
		let mut limb_stack = limb_stack.clone();
		let mut new_carries = Vec::new();

		if limb_stack.is_empty() {
			limb_stack.push(zero);
		}

		// Pad stack to handle incoming carries
		if limb_stack.len() < carries.len() + 1 {
			limb_stack.resize(carries.len() + 1, zero);
		}

		if limb_stack.len() == 1 {
			let single_wire = limb_stack[0];
			let carry_in = carries.pop().unwrap_or(zero);

			let (sum, cout) = builder.iadd_cin_cout(single_wire, zero, carry_in);
			sums.push(sum);
			new_carries.push(cout);
		} else {
			// We reduce the stack by repeatedly adding pairs until only one sum remains
			while limb_stack.len() >= 2 {
				let carry_in = carries.pop().unwrap_or(zero);
				let x = limb_stack.pop().expect("limb_stack.len() >= 2");
				let y = limb_stack.pop().expect("limb_stack.len() >= 2");

				if limb_stack.is_empty() {
					// This is the final addition for this limb position
					// The sum becomes the result for this position
					let (sum, cout) = builder.iadd_cin_cout(x, y, carry_in);
					sums.push(sum);
					new_carries.push(cout);
				} else {
					// Still have more values to add at this position
					// Push the intermediate sum back onto the stack
					let (sum, cout) = builder.iadd_cin_cout(x, y, carry_in);
					new_carries.push(cout);
					limb_stack.push(sum);
				}
			}
			assert!(limb_stack.is_empty());
		}

		assert!(carries.is_empty());
		carries = new_carries;
	}

	// Assert all final carries are zero (i.e no overflow).
	//
	// It is sufficient to check the MSB of each wire in `carries` because:
	//
	// - The `carries` vector stores carry_out from each iadd_cin_cout gate.
	// - The carry bit for each addition is stored in the MSB of the carry_out wire.
	for (i, carry) in carries.into_iter().enumerate() {
		let carry_msb = builder.shr(carry, 63);
		builder.assert_eq(format!("compute_stack_adds_carry_zero_{i}"), carry_msb, zero);
	}

	sums
}

/// Convert a slice of u64 limbs (little-endian ordering) to a BigUint.
///
/// # Arguments
/// * `slice` - Limbs in little-endian order (slice\[0\] is least significant)
///
/// # Returns
/// The value as a `BigUint` for arbitrary precision arithmetic
pub fn biguint_from_u64_slice(slice: &[u64]) -> BigUint {
	BigUint::from_bytes_le(
		&slice
			.iter()
			.flat_map(|&v| v.to_le_bytes())
			.collect::<Vec<u8>>(),
	)
}

/// Convert witness limbs to BigUint for computation.
///
/// This function is used during witness generation to extract the actual
/// numeric value from a bignum represented as wires in the circuit.
///
/// # Arguments
/// * `limbs` - Wire array representing the bignum in little-endian order
/// * `w` - Witness filler containing the actual values
///
/// # Returns
/// The bignum value as a `BigUint`
pub fn limbs_to_biguint(limbs: &[Wire], w: &WitnessFiller) -> BigUint {
	let limb_vals: Vec<_> = limbs.iter().map(|&l| w[l].as_u64()).collect();
	biguint_from_u64_slice(&limb_vals)
}
