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
	result
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
		// eventually we won't even store all these layers
		// so this will have to change anyway

		Ok(Layers { n_vars, layers })
	}

	fn n_vars(&self) -> usize {
		self.n_vars
	}

	pub fn clone_last_layer_last_buffer(&self) -> Result<FieldBuffer<P>, Error> {
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
	assert_eq!(a.log_len(), b.log_len());
	let mut result = FieldBuffer::<P>::zeros(a.log_len());
	for (result, a, b) in izip!(result.as_mut(), a.as_ref(), b.as_ref()) {
		*result = *a * *b;
	}
	Ok(result)
}

fn square_buffer<P: PackedField>(buffer: &mut [P]) {
	for val in buffer {
		*val = val.square();
	}
}

pub fn select_kth_for_constant_base<P: PackedField>(
	constant: P::Scalar,
	exponents: &[u64],
	dest: &mut [P],
	k: usize,
) {
	assert_eq!(dest.len() * P::WIDTH, exponents.len());

	for (exponents, dest) in izip!(exponents.chunks(P::WIDTH), dest) {
		let scalars = exponents.iter().map(|e| {
			if e & (1 << k) == 0 {
				P::Scalar::ONE
			} else {
				constant
			}
		});
		*dest = P::from_scalars(scalars);
	}
}

pub fn select_kth_for_variable_base<P: PackedField>(
	base: &[P],
	exponents: &[u64],
	dest: &mut [P],
	k: usize,
) {
	assert_eq!(base.len(), dest.len());
	assert_eq!(dest.len() * P::WIDTH, exponents.len());

	for (base, exponents, dest) in izip!(base, exponents.chunks(P::WIDTH), dest) {
		let scalars = P::iter(base)
			.zip(exponents)
			.map(|(b, e)| if e & (1 << k) == 0 { P::Scalar::ONE } else { b });
		*dest = P::from_scalars(scalars);
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

fn build_tree_layers<P: PackedField>(leaves: Vec<FieldBuffer<P>>) -> Result<Layers<P>, Error> {
	let depth = log2_exact(leaves.len());

	let mut layers = vec![];

	fn reduce_layer<P: PackedField>(
		buffers: &[FieldBuffer<P>],
	) -> Result<Vec<FieldBuffer<P>>, Error> {
		buffers
			.chunks(2)
			.map(|pair| compute_bivariate_product(pair[0].to_ref(), pair[1].to_ref()))
			.collect()
	}

	let mut current_layer = leaves;
	for _ in 0..depth {
		let my_layer = std::mem::take(&mut current_layer);
		current_layer = reduce_layer(&my_layer)?;
		layers.push(my_layer);
	}

	layers.push(current_layer);

	Layers::new(layers)
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

	let last_a_buffer = a_layers.clone_last_layer_last_buffer()?;
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

	fn check_consistency<P: PackedField>(data: &ProverData<P>) {
		let last_b_layer = data.b_layers.clone_last_layer_last_buffer().unwrap();
		let last_c_layer = data.c_layers.clone_last_layer_last_buffer().unwrap();

		assert_eq!(last_b_layer.log_len(), last_c_layer.log_len());
		for (b, c) in izip!(last_b_layer.as_ref(), last_c_layer.as_ref()) {
			assert_eq!(b, c);
		}
	}

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

		let data =
			execute::<P>(generator, &a_exponents, &b_exponents, &c_lo_exponents, &c_hi_exponents)
				.unwrap();
		check_consistency(&data);
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

		let data =
			execute::<P>(generator, &a_exponents, &b_exponents, &c_lo_exponents, &c_hi_exponents)
				.unwrap();
		check_consistency(&data);
	}

	#[test]
	fn test_forwards_multiple_random() {
		use rand::Rng;

		let mut rng = rand::rng();
		let generator = F::MULTIPLICATIVE_GENERATOR;

		const VECTOR_SIZE: usize = 8;
		let mut a_exponents = Vec::with_capacity(VECTOR_SIZE);
		let mut b_exponents = Vec::with_capacity(VECTOR_SIZE);
		let mut c_lo_exponents = Vec::with_capacity(VECTOR_SIZE);
		let mut c_hi_exponents = Vec::with_capacity(VECTOR_SIZE);

		for _ in 0..VECTOR_SIZE {
			let a_exp = rng.random_range(1..u64::MAX);
			let b_exp = rng.random_range(1..u64::MAX);

			let a_u128 = a_exp as u128;
			let b_u128 = b_exp as u128;
			let full_result = a_u128 * b_u128;
			let c_lo = full_result as u64;
			let c_hi = (full_result >> 64) as u64;

			a_exponents.push(a_exp);
			b_exponents.push(b_exp);
			c_lo_exponents.push(c_lo);
			c_hi_exponents.push(c_hi);
		}

		let data =
			execute::<P>(generator, &a_exponents, &b_exponents, &c_lo_exponents, &c_hi_exponents)
				.unwrap();
		check_consistency(&data);
	}
}
