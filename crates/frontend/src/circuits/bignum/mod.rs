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

#[cfg(test)]
mod tests;

use crate::{
	compiler::{CircuitBuilder, Wire},
	word::Word,
};

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
