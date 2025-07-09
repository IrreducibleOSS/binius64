//! Integer multiplication utilities and benchmarks

use binius_field::{Field, PackedField};
use binius_math::field_buffer::{FieldBuffer, FieldSlice, FieldSliceMut};
use itertools::izip;

mod error;
mod prove;
mod provers;

fn log2_exact(n: usize) -> usize {
	assert!(n > 0, "Cannot compute log2 of zero");
	assert!(n & (n - 1) == 0, "Number must be a power of 2");

	// Count the trailing zeros which gives us the log2 for a power of 2
	n.trailing_zeros() as usize
}

fn pow2_64<F: Field>(generator: F) -> F {
	let mut result = generator;
	for _ in 0..64 {
		result = result.square();
	}
	return result;
}

/// maybe they should take in field buffer references
fn compute_bivariate_product<P>(a: FieldSlice<P>, b: FieldSlice<P>) -> FieldBuffer<P>
where
	P: PackedField,
{
	assert_eq!(a.log_len(), b.log_len());
	let mut result = FieldBuffer::<P>::zeros(a.log_len());
	let result_slice = result.as_mut();
	let a_slice = a.as_ref();
	let b_slice = b.as_ref();
	for i in 0..result_slice.len() {
		result_slice[i] = a_slice[i] * b_slice[i];
	}
	result
}

fn square_buffer<P>(v: &mut [P])
where
	P: PackedField,
{
	for i in 0..v.len() {
		v[i] = v[i].square();
	}
}

pub fn select_kth_for_constant_base<P: PackedField>(
	constant: P::Scalar,
	exponents: &[u64],
	result: &mut [P],
	k: usize,
) {
	assert_eq!(result.len() * P::WIDTH, exponents.len());

	for (exponents, result) in izip!(exponents.chunks(P::WIDTH), result) {
		let scalars = exponents.iter().map(|e| {
			if e & (1 << k) == 0 {
				P::Scalar::ONE
			} else {
				constant
			}
		});
		*result = P::from_scalars(scalars);
	}
}

pub fn select_kth_for_variable_base<P: PackedField>(
	base: &[P],
	exponents: &[u64],
	result: &mut [P],
	k: usize,
) {
	assert_eq!(base.len(), result.len());
	assert_eq!(result.len() * P::WIDTH, exponents.len());

	for (base, exponents, result) in izip!(base, exponents.chunks(P::WIDTH), result) {
		let scalars = P::iter(base)
			.zip(exponents)
			.map(|(b, e)| if e & (1 << k) == 0 { P::Scalar::ONE } else { b });
		*result = P::from_scalars(scalars);
	}
}

fn generate_inputs_for_constant_base<P: PackedField>(
	generator: P::Scalar,
	exponents: &[u64],
) -> Vec<FieldBuffer<P>> {
	let conjugations = std::iter::successors(Some(generator), |&prev| Some(prev.square()))
		.take(64)
		.collect::<Vec<_>>();

	let log_len = log2_exact(exponents.len());
	let mut results = vec![];

	for k in 0..64 {
		let mut result = FieldBuffer::<P>::zeros(log_len);
		// so first issue here is above we want the results packed length to match with the
		// exponents... but that may not be the case if the exponents are fewer than the packed
		// width. in that case.
		select_kth_for_constant_base(conjugations[k], exponents, result.as_mut(), k);
		results.push(result);
	}
	results
}

// given the base and exponents, create the 64 selected conjugate field buffers
fn generate_inputs_for_variable_base<P: PackedField>(
	base: FieldSlice<P>,
	exponents: &[u64],
) -> Vec<FieldBuffer<P>> {
	let mut results = vec![];

	let mut temp = base.clone();
	for k in 0..64 {
		let mut result = temp.clone();
		select_kth_for_variable_base(temp.as_ref(), exponents, result.as_mut(), k);
		results.push(result);

		square_buffer(temp.as_mut());
	}
	results
}

/// takes 64 input field buffers and generates all layers and returns the last.
/// actually it should return all of them.
fn build_tree_layers<P: PackedField>(v: Vec<FieldBuffer<P>>) -> Layers<P> {
	assert_eq!(v.len(), 64, "Binary tree execution requires exactly 64 field buffers");

	fn reduce_layer<P: PackedField>(buffers: &[FieldBuffer<P>]) -> Vec<FieldBuffer<P>> {
		buffers
			.chunks(2)
			.map(|pair| compute_bivariate_product(pair[0].to_ref(), pair[1].to_ref()))
			.collect()
	}

	let layer1 = reduce_layer(&v);

	let layer2 = reduce_layer(&layer1);

	let layer3 = reduce_layer(&layer2);

	let layer4 = reduce_layer(&layer3);

	let layer5 = reduce_layer(&layer4);

	let layer6 = reduce_layer(&layer5);

	Layers::new::<64>(v, vec![layer1, layer2, layer3, layer4, layer5, layer6])
}

struct ProverData<'a, P: PackedField> {
	n_vars: usize,
	a_exponents: &'a [u64],
	b_exponents: &'a [u64],
	c_lo_exponents: &'a [u64],
	c_hi_exponents: &'a [u64],
	a_tree: Layers<P>,
	b_tree: Layers<P>,
	c_tree: Layers<P>,
}

/// depth 6 tree of layers
/// iterate to take owneship of each layer, leaves being last
pub struct Layers<P: PackedField> {
	n_vars: usize,
	layers: Vec<Vec<FieldBuffer<P>>>,
}

impl<P: PackedField> Layers<P> {
	fn new<const DEPTH: usize>(
		leaves: Vec<FieldBuffer<P>>,
		other_layers: Vec<Vec<FieldBuffer<P>>>,
	) -> Self {
		// actually make this generic over the depth. we'll only do 6 and 7.

		// assert_eq!(leaves.len(), 64);
		// assert_eq!(other_layers.len(), 6);

		// todo: check that each of the other layers has the correct number of field buffers
		// todo: check that each field buffer has the same log_len

		let first_leaf = leaves.first().expect("checked 64 leaves");
		let n_vars = first_leaf.log_len();

		let mut layers = vec![leaves];
		layers.extend(other_layers);

		Layers { n_vars, layers }
	}

	fn n_vars(&self) -> usize {
		self.n_vars
	}
}

impl<P: PackedField> Iterator for Layers<P> {
	type Item = Vec<FieldBuffer<P>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.layers.pop()
	}
}

fn execute_forwards<'a, P: PackedField>(
	generator: P::Scalar,
	a_exponents: &'a [u64],
	b_exponents: &'a [u64],
	c_lo_exponents: &'a [u64],
	c_hi_exponents: &'a [u64],
) -> ProverData<'a, P> {
	let a_layer_0 = generate_inputs_for_constant_base::<P>(generator, a_exponents);
	let c_lo_layer_0 = generate_inputs_for_constant_base::<P>(generator, c_lo_exponents);
	let c_hi_layer_0 = generate_inputs_for_constant_base::<P>(pow2_64(generator), c_hi_exponents);

	// so we first compute these three input layers.
	// then we call execute_binary_tree on them.
	let a_tree = build_binary_tree(a_layer_0);
	let c_lo_tree = build_binary_tree(c_lo_layer_0);
	let c_hi_tree = build_binary_tree(c_hi_layer_0);

	// take the final layer from those of c_lo and c_hi and join them
	let c_joining_layer =
		compute_bivariate_product(c_lo_tree.last_layer_buffer(), c_hi_tree.last_layer_buffer());

	let b_layer_0 = generate_inputs_for_variable_base(a_tree.last_layer_buffer(), b_exponents);
	let b_tree = build_binary_tree(b_layer_0);

	// println!("c_joining_layer: {:#?}", c_joining_layer);
	// println!("b_tree_layers last: {:#?}", b_tree_layers.last().unwrap().last().unwrap());

	ProverData {
		n_vars: a_tree.n_vars(),
		a_exponents,
		b_exponents,
		c_lo_exponents,
		c_hi_exponents,
		a_tree,
		b_tree,
		c_lo_tree,
		c_hi_tree,
		c_joining_layer,
	}
}

// fn int_mult(a: &[u64], b: &[u64], c_lo: &[u64], c_hi: &[u64]) {
// 	execute_forwards(a, b, c_lo, c_hi, &[]);
// }

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField, BinaryField128b, PackedBinaryField1x128b};

	use super::*;

	type F = BinaryField128b;
	type P = PackedBinaryField1x128b;

	// #[test]
	// fn test_forwards() {
	// 	// Use a simple example where a=2, b=3, c=6 (c_lo=6, c_hi=0)

	// 	// Get the generator for our field
	// 	let generator = F::MULTIPLICATIVE_GENERATOR;

	// 	// Create exponents: a=2, b=3, c=6 split into low/high parts
	// 	let a_exponent: u64 = 2;
	// 	let b_exponent: u64 = 3;
	// 	let c_lo_exponent: u64 = 6; // 2*3 = 6
	// 	let c_hi_exponent: u64 = 0; // No high bits for this small example

	// 	// Pack them into slices
	// 	let a_exponents = vec![a_exponent];
	// 	let b_exponents = vec![b_exponent];
	// 	let c_lo_exponents = vec![c_lo_exponent];
	// 	let c_hi_exponents = vec![c_hi_exponent];

	// 	// Call execute_forwards
	// 	execute_forwards::<P>(
	// 		generator,
	// 		&a_exponents,
	// 		&b_exponents,
	// 		&c_lo_exponents,
	// 		&c_hi_exponents,
	// 	);

	// 	// For a more complete test, we'd want to verify the results
	// 	// This would require execute_forwards to return a value
	// 	// and adding assertions to check that value
	// }

	#[test]
	fn test_forwards_larger() {
		// Use a larger example where the result has both low and high parts
		// a = 2^32, b = 2^33, c = 2^65 (c_lo=0, c_hi=2)

		// Get the generator for our field
		let generator = F::MULTIPLICATIVE_GENERATOR;

		// Create exponents
		let a_exponent: u64 = 1 << 32;
		let b_exponent: u64 = 1 << 33;
		let c_lo_exponent: u64 = 0;
		let c_hi_exponent: u64 = 2; // 2^32 * 2^33 = 2^65, which is 2 in the high 64 bits

		// Pack them into slices
		let a_exponents = vec![a_exponent];
		let b_exponents = vec![b_exponent];
		let c_lo_exponents = vec![c_lo_exponent];
		let c_hi_exponents = vec![c_hi_exponent];

		// Call execute_forwards
		execute_forwards::<P>(
			generator,
			&a_exponents,
			&b_exponents,
			&c_lo_exponents,
			&c_hi_exponents,
		);
	}

	#[test]
	fn test_forwards_multiple_random() {
		use rand::Rng;

		// Create a random number generator
		let mut rng = rand::rng();
		let generator = F::MULTIPLICATIVE_GENERATOR;

		// Create multiple random exponents
		const NUM_EXPONENTS: usize = 4; // Test with 4 pairs of numbers
		let mut a_exponents = Vec::with_capacity(NUM_EXPONENTS);
		let mut b_exponents = Vec::with_capacity(NUM_EXPONENTS);
		let mut c_lo_exponents = Vec::with_capacity(NUM_EXPONENTS);
		let mut c_hi_exponents = Vec::with_capacity(NUM_EXPONENTS);

		// Generate random exponents and compute expected results
		for _ in 0..NUM_EXPONENTS {
			// Generate random 32-bit exponents to ensure multiplication doesn't overflow u64
			let a_exp = rng.random_range(1..100_000) as u64;
			let b_exp = rng.random_range(1..100_000) as u64;

			// Calculate expected result (a * b)
			let full_result = a_exp.wrapping_mul(b_exp);
			let c_lo = full_result; // For u64 * u64, result fits in 64 bits
			let c_hi = 0; // For these small numbers, high bits will be 0

			// Store the exponents
			a_exponents.push(a_exp);
			b_exponents.push(b_exp);
			c_lo_exponents.push(c_lo);
			c_hi_exponents.push(c_hi);

			// Print the values for debugging
			println!(
				"a: {}, b: {}, expected product: {} (lo: {}, hi: {})",
				a_exp, b_exp, full_result, c_lo, c_hi
			);
		}

		// Generate some larger numbers that will have high bits
		for _ in 0..2 {
			// Generate values where multiplication will produce high bits
			let a_exp = (1u64 << 40) + rng.random_range(1..100_000) as u64;
			let b_exp = (1u64 << 40) + rng.random_range(1..100_000) as u64;

			// Calculate expected result using 128-bit arithmetic
			let a_128 = a_exp as u128;
			let b_128 = b_exp as u128;
			let full_result = a_128 * b_128;

			let c_lo = (full_result & 0xFFFF_FFFF_FFFF_FFFF) as u64;
			let c_hi = (full_result >> 64) as u64;

			// Store the exponents
			a_exponents.push(a_exp);
			b_exponents.push(b_exp);
			c_lo_exponents.push(c_lo);
			c_hi_exponents.push(c_hi);

			println!(
				"Large a: {}, b: {}, expected product: {} (lo: {}, hi: {})",
				a_exp, b_exp, full_result, c_lo, c_hi
			);
		}

		// Call execute_forwards with all exponents
		execute_forwards::<P>(
			generator,
			&a_exponents,
			&b_exponents,
			&c_lo_exponents,
			&c_hi_exponents,
		);

		// For a complete test, we'd verify the results returned by execute_forwards
		// This would require modifying execute_forwards to return a result that can be validated
	}
}
