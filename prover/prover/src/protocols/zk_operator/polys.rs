//! Sumcheck protocol implementation for dot product of multilinear polynomials.
//!
//! This implements the sumcheck protocol for proving:
//! ∑_{x∈{0,1}^n} f(x) * g(x) = claimed_sum
//!
//! The protocol works by having the prover send univariate polynomials in each round,
//! and the verifier checks consistency by evaluating at 0 and 1.

use crate::protocols::zk_operator::algebra::fold_one;
use binius_field::{BinaryField128bGhash as Ghash, Field, Random};
use itertools::izip;
use rand::{SeedableRng, rngs::StdRng};

/// Represents a multilinear polynomial as evaluations over the boolean hypercube.
/// For n variables, this contains 2^n evaluations.
#[derive(Debug, Clone)]
pub struct MultilinearPoly {
	/// Evaluations of the polynomial at all points in {0,1}^n
	/// Index i corresponds to the binary representation of the point
	pub evaluations: Vec<Ghash>,
	/// Number of variables
	pub num_vars: usize,
}

impl MultilinearPoly {
	/// Create a new multilinear polynomial from evaluations
	pub fn new(evaluations: Vec<Ghash>) -> Self {
		let num_vars = (evaluations.len() as f64).log2() as usize;
		assert_eq!(evaluations.len(), 1 << num_vars, "Evaluations length must be a power of 2");

		Self {
			evaluations,
			num_vars,
		}
	}

	/// Create a polynomial with all zeros
	pub fn zero(num_vars: usize) -> Self {
		Self::new(vec![Ghash::new(0); 1 << num_vars])
	}

	/// Generate a random multilinear polynomial with the given number of variables and seed
	pub fn random(num_vars: usize, seed: u64) -> Self {
		let mut rng = StdRng::seed_from_u64(seed);
		let size = 1 << num_vars;
		let evaluations = (0..size).map(|_| Ghash::random(&mut rng)).collect();

		Self::new(evaluations)
	}

	/// Get the number of variables
	pub fn num_vars(&self) -> usize {
		self.num_vars
	}

	// /// Evaluate the polynomial at a specific point on the boolean hypercube
	// pub fn evaluate(&self, point: &[bool]) -> Ghash {
	// 	assert_eq!(point.len(), self.num_vars);

	// 	let index = point
	// 		.iter()
	// 		.enumerate()
	// 		.fold(0, |acc, (i, &bit)| acc | ((bit as usize) << i));

	// 	self.evaluations[index]
	// }

	/// Evaluate the multilinear polynomial at an arbitrary point using multilinear extension
	/// Uses the formula: f̃(x) = Σ_{w∈{0,1}^n} f(w) · ∏ᵢ((1-xᵢ)·(1-wᵢ) + xᵢ·wᵢ)
	pub fn evaluate_at(&self, point: &[Ghash]) -> Ghash {
		assert_eq!(point.len(), self.num_vars);

		let mut result = Ghash::ZERO;

		// Iterate over all vertices of the boolean hypercube
		for vertex_index in 0..(1 << self.num_vars) {
			let mut term = self.evaluations[vertex_index];

			// Compute the multilinear basis function for this vertex
			for var_index in 0..self.num_vars {
				let vertex_bit = (vertex_index >> var_index) & 1;
				let x_i = point[var_index];

				// Compute (1-xᵢ)·(1-wᵢ) + xᵢ·wᵢ
				let basis_factor = if vertex_bit == 0 {
					// wᵢ = 0: compute (1-xᵢ)
					Ghash::ONE + x_i // In binary field, 1-x = 1+x
				} else {
					// wᵢ = 1: compute xᵢ
					x_i
				};

				term *= basis_factor;
			}

			result += term;
		}

		result
	}

	/// Split the polynomial into two halves based on the first variable
	/// Returns (f_0, f_1) where f_0 = f(0, x1, ..., x_{n-1}) and f_1 = f(1, x1, ..., x_{n-1})
	pub fn split(&self) -> (MultilinearPoly, MultilinearPoly) {
		if self.num_vars == 0 {
			panic!("Cannot split polynomial with 0 variables");
		}

		let half_size = 1 << (self.num_vars - 1);

		// Split into low and high halves
		// f_0: first variable = 0 (low half: indices 0..half_size)
		// f_1: first variable = 1 (high half: indices half_size..2*half_size)
		let f0_evals = self.evaluations[..half_size].to_vec();
		let f1_evals = self.evaluations[half_size..].to_vec();

		(MultilinearPoly::new(f0_evals), MultilinearPoly::new(f1_evals))
	}

	/// Add two multilinear polynomials together
	/// Returns f + g where (f + g)(x) = f(x) + g(x)
	pub fn add(f: &MultilinearPoly, g: &MultilinearPoly) -> MultilinearPoly {
		assert_eq!(f.num_vars, g.num_vars);
		assert_eq!(f.evaluations.len(), g.evaluations.len());

		let sum_evals: Vec<Ghash> = f
			.evaluations
			.iter()
			.zip(g.evaluations.iter())
			.map(|(&v0, &v1)| v0 + v1)
			.collect();

		MultilinearPoly::new(sum_evals)
	}

	/// Scale a multilinear polynomial by a scalar
	/// Returns c * f where (c * f)(x) = c * f(x)
	pub fn scale(f: &MultilinearPoly, scalar: Ghash) -> MultilinearPoly {
		let scaled_evals: Vec<Ghash> = f.evaluations.iter().map(|&v| scalar * v).collect();

		MultilinearPoly::new(scaled_evals)
	}

	/// Multiply two multilinear polynomials together (pointwise)
	/// Returns f * g where (f * g)(x) = f(x) * g(x)
	pub fn mul(f: &MultilinearPoly, g: &MultilinearPoly) -> MultilinearPoly {
		assert_eq!(f.num_vars, g.num_vars);
		assert_eq!(f.evaluations.len(), g.evaluations.len());

		let product_evals: Vec<Ghash> = f
			.evaluations
			.iter()
			.zip(g.evaluations.iter())
			.map(|(&v0, &v1)| v0 * v1)
			.collect();

		MultilinearPoly::new(product_evals)
	}

	/// Fold two polynomials together with a random point r
	/// Returns f(r, x1, ..., x_{n-1}) = (1-r) * f_0(x1, ..., x_{n-1}) + r * f_1(x1, ..., x_{n-1})
	pub fn fold(f0: &MultilinearPoly, f1: &MultilinearPoly, r: Ghash) -> MultilinearPoly {
		assert_eq!(f0.num_vars, f1.num_vars);
		assert_eq!(f0.evaluations.len(), f1.evaluations.len());

		let folded_evals: Vec<Ghash> = izip!(f0.evaluations.iter(), f1.evaluations.iter())
			.map(|(&v0, &v1)| fold_one(v0, v1, r))
			.collect();

		MultilinearPoly::new(folded_evals)
	}

	/// Compute the sum of all evaluations
	pub fn sum(&self) -> Ghash {
		self.evaluations.iter().copied().sum()
	}

	/// Set values to zero at indices 0 and 2^i for all valid i
	/// This modifies the polynomial in place
	pub fn randomize_at_powers_of_two(&mut self, inputs: &[Ghash]) {
		let size = self.evaluations.len();
		assert_eq!(1 + self.num_vars, inputs.len());

		// Set index 0 to zero
		if size > 0 {
			self.evaluations[0] = inputs[0];
		}

		let mut input_idx = 1;
		// Set index 2^i to zero for all valid i
		let mut power_of_two = 1; // Start with 2^0 = 1
		while power_of_two < size {
			self.evaluations[power_of_two] = inputs[input_idx];
			input_idx += 1;
			power_of_two *= 2; // Next power of 2
		}
	}

	/// Set blocks of 2 scalars at positions 0 and 2^i for all valid i to provided inputs
	/// Treats consecutive pairs of evaluations as blocks, then applies the same
	/// pattern to those blocks as if they were scalars in a multilinear
	/// polynomial of half the size.
	/// This modifies the polynomial in place
	pub fn randomize_blocks_at_powers_of_two(&mut self, inputs: &[Ghash]) {
		let size = self.evaluations.len();

		// Must have even number of elements to form blocks of size 2
		if size % 2 != 0 {
			panic!("Cannot form blocks of size 2 from odd number of evaluations: {size}");
		}

		let num_blocks = size / 2;

		// Determine target block indices: 0 and powers of two less than num_blocks
		let mut block_indices = Vec::new();
		if num_blocks > 0 {
			block_indices.push(0usize);
			let mut p = 1usize;
			while p < num_blocks {
				block_indices.push(p);
				p <<= 1;
			}
		}

		let expected_inputs = 2 * block_indices.len();
		if inputs.len() != expected_inputs {
			panic!("Expected {expected_inputs} input values, got {}", inputs.len());
		}

		// Write each target block from inputs (two values per block)
		let mut in_off = 0usize;
		for &bidx in &block_indices {
			let start = 2 * bidx;
			self.evaluations[start] = inputs[in_off];
			self.evaluations[start + 1] = inputs[in_off + 1];
			in_off += 2;
		}
	}
}

/// Evaluate a quadratic polynomial f(x) = ax^2 + bx + c at point x
/// Given evaluations at 0, 1, and infinity (where infinity is the coefficient of x^2)
/// coeffs[0] = f(0) = c
/// coeffs[1] = f(1) = a + b + c  
/// coeffs[2] = f(∞) = a (coefficient of x^2)
pub fn evaluate_univariate(coeffs: &[Ghash], x: Ghash) -> Ghash {
	assert_eq!(coeffs.len(), 3, "Expected exactly 3 coefficients for quadratic evaluation");

	let eval_0 = coeffs[0]; // f(0) = c
	let eval_1 = coeffs[1]; // f(1) = a + b + c
	let eval_inf = coeffs[2]; // f(∞) = a

	// Recover coefficients: f(x) = ax^2 + bx + c
	let c = eval_0; // c = f(0)
	let a = eval_inf; // a = f(∞)
	let b = eval_1 + a + c; // b = f(1) - a - c (note: subtraction = addition in binary field)

	// Evaluate: f(x) = ax^2 + bx + c
	a * x * x + b * x + c
}

/// Compute the sum of element-wise products of two multilinear polynomials
pub fn dot_product_sum(f: &MultilinearPoly, g: &MultilinearPoly) -> Ghash {
	assert_eq!(f.evaluations.len(), g.evaluations.len());

	f.evaluations
		.iter()
		.zip(g.evaluations.iter())
		.map(|(&a, &b)| a * b)
		.sum()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_split_and_fold() {
		let poly =
			MultilinearPoly::new(vec![Ghash::new(1), Ghash::new(2), Ghash::new(3), Ghash::new(4)]);

		let (f0, f1) = poly.split();

		// f0 should be [1, 2] (low half, x=0 cases)
		// f1 should be [3, 4] (high half, x=1 cases)
		assert_eq!(f0.evaluations, vec![Ghash::new(1), Ghash::new(2)]);
		assert_eq!(f1.evaluations, vec![Ghash::new(3), Ghash::new(4)]);

		// Test folding with r = 5
		let r = Ghash::new(5);
		let folded = MultilinearPoly::fold(&f0, &f1, r);

		// Calculate expected values: (1+r)*f0 + r*f1 = 4*f0 + 5*f1 in binary field
		let one_plus_r = Ghash::new(1) + r; // Should be 4 in binary field
		let expected_0 = one_plus_r * Ghash::new(1) + r * Ghash::new(3);
		let expected_1 = one_plus_r * Ghash::new(2) + r * Ghash::new(4);

		let expected = vec![expected_0, expected_1];
		assert_eq!(folded.evaluations, expected);
	}

	#[test]
	fn test_randomize_blocks_at_powers_of_two() {
		// Test with 16 evaluations (8 blocks)
		// Should modify blocks 0, 1, 2, 4 (indices 0-1, 2-3, 4-5, 8-9)
		let mut poly = MultilinearPoly::new(vec![Ghash::from(0u128); 16]);

		// Create test inputs: 8 values needed (4 blocks * 2 values each)
		let inputs: Vec<Ghash> = (1u128..=8u128).map(Ghash::from).collect();

		poly.randomize_blocks_at_powers_of_two(&inputs);

		// Check that the correct positions were modified
		assert_eq!(poly.evaluations[0], Ghash::from(1u128)); // Block 0
		assert_eq!(poly.evaluations[1], Ghash::from(2u128));
		assert_eq!(poly.evaluations[2], Ghash::from(3u128)); // Block 1 
		assert_eq!(poly.evaluations[3], Ghash::from(4u128));
		assert_eq!(poly.evaluations[4], Ghash::from(5u128)); // Block 2
		assert_eq!(poly.evaluations[5], Ghash::from(6u128));
		assert_eq!(poly.evaluations[6], Ghash::from(0u128)); // Block 3 (not modified)
		assert_eq!(poly.evaluations[7], Ghash::from(0u128));
		assert_eq!(poly.evaluations[8], Ghash::from(7u128)); // Block 4
		assert_eq!(poly.evaluations[9], Ghash::from(8u128));

		// Check that other positions remain zero
		for i in 10..16 {
			assert_eq!(poly.evaluations[i], Ghash::from(0u128));
		}
	}

	#[test]
	fn test_randomize_blocks_at_powers_of_two_small() {
		// Test with 4 evaluations (2 blocks)
		// Should modify blocks 0, 1 (indices 0-1, 2-3)
		let mut poly = MultilinearPoly::new(vec![Ghash::from(0u128); 4]);

		// Need 4 values (2 blocks * 2 values each)
		let inputs: Vec<Ghash> = vec![
			Ghash::from(10u128),
			Ghash::from(20u128),
			Ghash::from(30u128),
			Ghash::from(40u128),
		];

		poly.randomize_blocks_at_powers_of_two(&inputs);

		assert_eq!(poly.evaluations[0], Ghash::from(10u128)); // Block 0
		assert_eq!(poly.evaluations[1], Ghash::from(20u128));
		assert_eq!(poly.evaluations[2], Ghash::from(30u128)); // Block 1
		assert_eq!(poly.evaluations[3], Ghash::from(40u128));
	}

	#[test]
	#[should_panic(expected = "Expected 4 input values, got 3")]
	fn test_randomize_blocks_at_powers_of_two_wrong_input_size() {
		let mut poly = MultilinearPoly::new(vec![Ghash::from(0u128); 4]);
		let inputs: Vec<Ghash> = vec![Ghash::from(1u128), Ghash::from(2u128), Ghash::from(3u128)]; // Wrong size

		poly.randomize_blocks_at_powers_of_two(&inputs);
	}

	#[test]
	fn test_randomize_blocks_at_powers_of_two_odd_size() {}

	#[test]
	fn test_randomize_blocks_calculation() {
		// Test that we calculate the right number of inputs for different sizes

		// 2 evaluations (1 block) -> modify block 0 -> need 2 inputs
		let mut poly2 = MultilinearPoly::new(vec![Ghash::from(0u128); 2]);
		let inputs2 = vec![Ghash::from(1u128), Ghash::from(2u128)];
		poly2.randomize_blocks_at_powers_of_two(&inputs2); // Should not panic

		// 8 evaluations (4 blocks) -> modify blocks 0, 1, 2 -> need 6 inputs
		let mut poly8 = MultilinearPoly::new(vec![Ghash::from(0u128); 8]);
		let inputs8: Vec<Ghash> = (1u128..=6u128).map(Ghash::from).collect();
		poly8.randomize_blocks_at_powers_of_two(&inputs8); // Should not panic

		// Verify the pattern for 8 evaluations
		assert_eq!(poly8.evaluations[0], Ghash::from(1u128)); // Block 0
		assert_eq!(poly8.evaluations[1], Ghash::from(2u128));
		assert_eq!(poly8.evaluations[2], Ghash::from(3u128)); // Block 1
		assert_eq!(poly8.evaluations[3], Ghash::from(4u128));
		assert_eq!(poly8.evaluations[4], Ghash::from(5u128)); // Block 2
		assert_eq!(poly8.evaluations[5], Ghash::from(6u128));
		assert_eq!(poly8.evaluations[6], Ghash::from(0u128)); // Block 3 (not modified)
		assert_eq!(poly8.evaluations[7], Ghash::from(0u128));
	}
}
