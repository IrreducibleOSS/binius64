//! Arbitrary-precision bignum arithmetic for circuits.
//!
//! This module provides operations on big integers represented as vectors of `Wire` elements,
//! where each `Wire` represents a 64-bit limb. The representation uses little-endian ordering,
//! meaning the least significant limb is at index 0.

#[cfg(test)]
mod tests;

use crate::{
	compiler::{CircuitBuilder, Wire, WitnessFiller},
	word::Word,
};

/// Represents an arbitrarily large unsigned integer using a vector of `Wire`s
///
/// - Each `Wire` holds a 64-bit unsigned integer value (a "limb")
/// - Limbs are stored in little-endian order (index 0 = least significant)
/// - The total bit width is always a multiple of 64 bits (number of limbs × 64)
pub struct BigNum {
	pub limbs: Vec<Wire>,
}

impl BigNum {
	/// Creates a new BigNum with the given number of limbs as inout wires.
	pub fn new_inout(b: &CircuitBuilder, num_limbs: usize) -> Self {
		let limbs = (0..num_limbs).map(|_| b.add_inout()).collect();
		BigNum { limbs }
	}

	/// Creates a new Bignum with the given number of limbs as witness wires.
	pub fn new_witness(b: &CircuitBuilder, num_limbs: usize) -> Self {
		let limbs = (0..num_limbs).map(|_| b.add_witness()).collect();
		BigNum { limbs }
	}

	/// Populate the BigNum with the expected limb_values
	///
	/// Panics if limb_values.len() != self.limbs.len()
	pub fn populate_limbs(&self, w: &mut WitnessFiller, limb_values: &[u64]) {
		assert!(limb_values.len() == self.limbs.len());
		for (&wire, &v) in self.limbs.iter().zip(limb_values.iter()) {
			w[wire] = Word::from_u64(v);
		}
	}
}

/// Multiply two arbitrary-sized `BigNum`s.
///
/// Computes `a * b` where both inputs are `BigNum`s. The result will have
/// `a.limbs.len() + b.limbs.len()` limbs to accommodate the full product
/// without overflow.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First operand `BigNum`
/// * `b` - Second operand `BigNum`
///
/// # Returns
/// Product `BigNum` with `a.limbs.len() + b.limbs.len()` limbs
pub fn mul(builder: &CircuitBuilder, a: &BigNum, b: &BigNum) -> BigNum {
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

/// Square an arbitrary-sized `BigNum`.
///
/// Computes `a * a` using an optimized algorithm that takes advantage of the symmetry
/// in squaring (each cross-product appears twice). This is more efficient than
/// using general multiplication.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - The `BigNum` to be squared
///
/// # Returns
/// The square of `a` as a `BigNum` with `2 * a.limbs.len()` limbs
pub fn square(builder: &CircuitBuilder, a: &BigNum) -> BigNum {
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

/// Compare two arbitrary-sized `BigNum`s for equality.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First operand `BigNum`
/// * `b` - Second operand `BigNum` (must have same number of limbs as `a`)
///
/// # Returns
/// A `Wire` that evaluates to:
/// - `0xFFFFFFFFFFFFFFFF` (all ones) if `a == b`
/// - `0x0000000000000000` (all zeros) if `a != b`
///
/// # Panics
/// Panics if `a` and `b` have different number of limbs.
pub fn compare(builder: &CircuitBuilder, a: &BigNum, b: &BigNum) -> Wire {
	assert_eq!(a.limbs.len(), b.limbs.len(), "compare: inputs must have the same number of limbs");

	if a.limbs.is_empty() {
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
		.limbs
		.iter()
		.zip(b.limbs.iter())
		.map(|(&x, &y)| builder.icmp_eq(x, y))
		.collect();

	// AND all equality results together
	eq_results
		.into_iter()
		.reduce(|acc, x| builder.band(acc, x))
		.unwrap()
}

/// Add two arbitrary-sized `BigNums`s with carry propagation.
///
/// Computes `a + b` with proper carry handling between limbs. The result
/// has the same number of limbs as the inputs. Overflow beyond the most
/// significant limb is checked and must be zero.
///
/// # Arguments
/// * `builder` - Circuit builder for constraint generation
/// * `a` - First operand
/// * `b` - Second operand (must have same number of limbs as `a`)
///
/// # Returns
/// Sum as a `BigNum` with the same number of limbs as the inputs
///
/// # Panics
/// - Panics if `a` and `b` have different number of limbs
pub fn add(builder: &CircuitBuilder, a: &BigNum, b: &BigNum) -> BigNum {
	assert_eq!(a.limbs.len(), b.limbs.len(), "add: inputs must have the same number of limbs");

	let mut accumulator = vec![vec![]; a.limbs.len()];
	for i in 0..a.limbs.len() {
		accumulator[i].push(a.limbs[i]);
		accumulator[i].push(b.limbs[i]);
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
fn compute_stack_adds(builder: &CircuitBuilder, limb_stacks: &[Vec<Wire>]) -> BigNum {
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

	BigNum { limbs: sums }
}

/// Modular reduction verification for BigNum.
///
/// This circuit verifies that:
///
/// a = quotient * modulus + remainder
pub struct ModReduce {
	pub a: BigNum,
	pub modulus: BigNum,
	pub quotient: BigNum,
	pub remainder: BigNum,
}

impl ModReduce {
	/// Creates a new modular reduction verifier circuit.
	///
	/// # Arguments
	/// * `builder` - Circuit builder for constraint generation
	/// * `a` - The dividend
	/// * `modulus` - The divisor
	/// * `quotient` - The quotient
	/// * `remainder` - The remainder
	///
	/// # Constraints
	/// The circuit enforces that `a = quotient * modulus + remainder`
	pub fn new(
		builder: &CircuitBuilder,
		a: BigNum,
		modulus: BigNum,
		quotient: BigNum,
		remainder: BigNum,
	) -> Self {
		let zero = builder.add_constant(Word::ZERO);

		let product = mul(builder, &quotient, &modulus);

		let mut remainder_padded = remainder.limbs.clone();
		remainder_padded.resize(product.limbs.len(), zero);
		let remainder_padded = BigNum {
			limbs: remainder_padded,
		};

		let reconstructed = add(builder, &product, &remainder_padded);

		let mut a_padded = a.limbs.clone();
		a_padded.resize(reconstructed.limbs.len(), zero);
		let a_padded = BigNum { limbs: a_padded };

		let eq = compare(builder, &reconstructed, &a_padded);
		let all_ones = builder.add_constant(Word::ALL_ONE);
		builder.assert_eq("mod_reduce_reconstruction", eq, all_ones);

		ModReduce {
			a,
			modulus,
			quotient,
			remainder,
		}
	}
}
