use binius_field::{Field, PackedField};
use binius_math::field_buffer::{FieldBuffer, FieldSlice};
use itertools::izip;

use super::error::Error;

pub fn log2_exact(n: usize) -> usize {
	assert!(n > 0, "Cannot compute log2 of zero");
	assert!(n & (n - 1) == 0, "Number must be a power of 2");
	n.trailing_zeros() as usize
}

fn pow2_64<F: Field>(generator: F) -> F {
	let mut result = generator;
	for _ in 0..64 {
		result = result.square();
	}
	return result;
}

#[derive(Debug)]
pub struct Layers<P: PackedField> {
	n_vars: usize,
	layers: Vec<Vec<FieldBuffer<P>>>,
}

impl<P: PackedField> Layers<P> {
	fn new(layers: Vec<Vec<FieldBuffer<P>>>) -> Result<Self, Error> {
		let last_layer = layers.last().ok_or(Error::LayersEmpty)?;
		let last_buffer = last_layer.last().ok_or(Error::LastLayerEmpty)?;

		let n_vars = last_buffer.log_len();

		// for now assume the layers are of the right sizes
		// and all buffers are the same length

		Ok(Layers { n_vars, layers })
	}

	fn n_vars(&self) -> usize {
		self.n_vars
	}

	pub fn last_layer_last_buffer(&self) -> Result<FieldBuffer<P>, Error> {
		let last_layer = self.layers.last().ok_or(Error::LayersEmpty)?;
		let last_buffer = last_layer.last().ok_or(Error::LastLayerEmpty)?;
		Ok(last_buffer.clone())
	}
}

impl<P: PackedField> IntoIterator for Layers<P> {
	type Item = Vec<FieldBuffer<P>>;
	type IntoIter = LayersIterator<P>;

	fn into_iter(self) -> Self::IntoIter {
		LayersIterator {
			layers: self.layers,
		}
	}
}

pub struct LayersIterator<P: PackedField> {
	layers: Vec<Vec<FieldBuffer<P>>>,
}

impl<P: PackedField> Iterator for LayersIterator<P> {
	type Item = Vec<FieldBuffer<P>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.layers.pop()
	}
}

pub struct ProverData<'a, P: PackedField> {
	pub n_vars: usize,
	pub a_exponents: &'a [u64],
	pub b_exponents: &'a [u64],
	pub c_lo_exponents: &'a [u64],
	pub c_hi_exponents: &'a [u64],
	pub a_layers: Layers<P>,
	pub b_layers: Layers<P>,
	pub c_layers: Layers<P>,
}

pub fn compute_bivariate_product<P: PackedField>(
	a: FieldSlice<P>,
	b: FieldSlice<P>,
) -> Result<FieldBuffer<P>, Error> {
	if a.log_len() != b.log_len() {
		return Err(Error::MultilinearSizeMismatch);
	}
	let mut result = FieldBuffer::<P>::zeros(a.log_len());
	let result_slice = result.as_mut();
	let a_slice = a.as_ref();
	let b_slice = b.as_ref();
	for (result, a, b) in izip!(result_slice, a_slice, b_slice) {
		*result = *a * *b;
	}
	Ok(result)
}

fn square_buffer<P: PackedField>(v: &mut [P]) {
	for val in v {
		*val = val.square();
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
	let depth = 6;
	let num_elements = 1 << depth;

	let conjugations = std::iter::successors(Some(generator), |&prev| Some(prev.square()))
		.take(num_elements)
		.collect::<Vec<_>>();

	let log_len = log2_exact(exponents.len());
	let mut results = vec![];

	for k in 0..num_elements {
		let mut result = FieldBuffer::<P>::zeros(log_len);
		select_kth_for_constant_base(conjugations[k], exponents, result.as_mut(), k);
		results.push(result);
	}
	results
}

fn generate_inputs_for_variable_base<P: PackedField>(
	base: FieldBuffer<P>,
	exponents: &[u64],
) -> Vec<FieldBuffer<P>> {
	let mut results = vec![];

	let mut temp = base;
	for k in 0..64 {
		let mut result = temp.clone();
		select_kth_for_variable_base(temp.as_ref(), exponents, result.as_mut(), k);
		results.push(result);

		square_buffer(temp.as_mut());
	}
	results
}

fn build_tree_layers<P: PackedField>(v: Vec<FieldBuffer<P>>) -> Result<Layers<P>, Error> {
	let depth = log2_exact(v.len());

	let mut layers = vec![];

	fn reduce_layer<P: PackedField>(
		buffers: &[FieldBuffer<P>],
	) -> Result<Vec<FieldBuffer<P>>, Error> {
		buffers
			.chunks(2)
			.map(|pair| compute_bivariate_product(pair[0].to_ref(), pair[1].to_ref()))
			.collect()
	}

	let mut current_layer = v;

	for _ in 0..depth {
		let my_layer = std::mem::take(&mut current_layer);
		current_layer = reduce_layer(&my_layer)?;
		layers.push(my_layer);
	}

	layers.push(current_layer);

	Ok(Layers::new(layers)?)
}

pub fn execute<'a, P: PackedField>(
	generator: P::Scalar,
	a_exponents: &'a [u64],
	b_exponents: &'a [u64],
	c_lo_exponents: &'a [u64],
	c_hi_exponents: &'a [u64],
) -> Result<ProverData<'a, P>, Error> {
	let a_leaves = generate_inputs_for_constant_base::<P>(generator, a_exponents);
	let c_lo_leaves = generate_inputs_for_constant_base::<P>(generator, c_lo_exponents);
	let c_hi_leaves = generate_inputs_for_constant_base::<P>(pow2_64(generator), c_hi_exponents);

	let mut c_leaves = vec![];
	c_leaves.extend(c_lo_leaves);
	c_leaves.extend(c_hi_leaves);

	let a_layers = build_tree_layers(a_leaves)?;
	let c_layers = build_tree_layers(c_leaves)?;

	let last_a_buffer = a_layers.last_layer_last_buffer()?;
	let b_leaves = generate_inputs_for_variable_base(last_a_buffer, b_exponents);
	let b_layers = build_tree_layers(b_leaves)?;

	Ok(ProverData {
		n_vars: a_layers.n_vars(),
		a_exponents,
		b_exponents,
		c_lo_exponents,
		c_hi_exponents,
		a_layers,
		b_layers,
		c_layers,
	})
}

#[cfg(test)]
mod tests {
	use binius_field::{BinaryField, BinaryField128b, PackedBinaryField1x128b};

	use super::*;

	type F = BinaryField128b;
	type P = PackedBinaryField1x128b;

	#[test]
	fn test_forwards() {
		let generator = F::MULTIPLICATIVE_GENERATOR;

		let a_exponent: u64 = 2;
		let b_exponent: u64 = 3;
		let c_lo_exponent: u64 = 6; // 2*3 = 6
		let c_hi_exponent: u64 = 0; // no high bits

		let a_exponents = vec![a_exponent];
		let b_exponents = vec![b_exponent];
		let c_lo_exponents = vec![c_lo_exponent];
		let c_hi_exponents = vec![c_hi_exponent];

		execute::<P>(generator, &a_exponents, &b_exponents, &c_lo_exponents, &c_hi_exponents)
			.unwrap();
	}

	#[test]
	fn test_forwards_larger() {
		let generator = F::MULTIPLICATIVE_GENERATOR;

		let a_exponent: u64 = 1 << 32;
		let b_exponent: u64 = 1 << 33;
		let c_lo_exponent: u64 = 0;
		let c_hi_exponent: u64 = 2; // 2^32 * 2^33 = 2^65, which is 2 in the high 64 bits

		let a_exponents = vec![a_exponent];
		let b_exponents = vec![b_exponent];
		let c_lo_exponents = vec![c_lo_exponent];
		let c_hi_exponents = vec![c_hi_exponent];

		execute::<P>(generator, &a_exponents, &b_exponents, &c_lo_exponents, &c_hi_exponents)
			.unwrap();
	}

	#[test]
	fn test_forwards_multiple_random() {
		use rand::Rng;

		// Create a random number generator
		let mut rng = rand::rng();
		let generator = F::MULTIPLICATIVE_GENERATOR;

		// Create multiple random exponents
		// We need vectors with power-of-2 length: choose 8 (2³)
		const VECTOR_SIZE: usize = 8; // Pad to 8 (next power of 2)
		let mut a_exponents = Vec::with_capacity(VECTOR_SIZE);
		let mut b_exponents = Vec::with_capacity(VECTOR_SIZE);
		let mut c_lo_exponents = Vec::with_capacity(VECTOR_SIZE);
		let mut c_hi_exponents = Vec::with_capacity(VECTOR_SIZE);

		// Generate random exponents and compute expected results
		for _ in 0..4 {
			// Generate 4 small number pairs
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

		// Pad with zeros to make the vector length a power of 2 (8)
		while a_exponents.len() < VECTOR_SIZE {
			a_exponents.push(0);
			b_exponents.push(0);
			c_lo_exponents.push(0);
			c_hi_exponents.push(0);
			println!("Adding padding entry to reach power-of-2 length");
		}

		// Verify we have a power-of-2 length
		let length = a_exponents.len();
		assert_eq!(length & (length - 1), 0, "Vector length must be a power of 2");
		println!("Vector length: {}", length);

		// Call execute_forwards with all exponents
		execute::<P>(generator, &a_exponents, &b_exponents, &c_lo_exponents, &c_hi_exponents)
			.unwrap();
	}
}
