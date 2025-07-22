// Copyright 2024-2025 Irreducible Inc.

use std::ops::Deref;

use binius_field::{ExtensionField, Field, PackedField};
use binius_utils::rayon::prelude::*;

use crate::FieldBuffer;

#[inline]
pub fn inner_product<F: Field>(
	a: impl IntoIterator<Item = F>,
	b: impl IntoIterator<Item = F>,
) -> F {
	inner_product_subfield(a, b)
}

#[inline]
pub fn inner_product_subfield<F, FSub>(
	a: impl IntoIterator<Item = FSub>,
	b: impl IntoIterator<Item = F>,
) -> F
where
	F: Field + ExtensionField<FSub>,
	FSub: Field,
{
	itertools::zip_eq(a, b).map(|(a_i, b_i)| b_i * a_i).sum()
}

#[inline]
pub fn inner_product_par<F, P, DataA, DataB>(
	a: &FieldBuffer<P, DataA>,
	b: &FieldBuffer<P, DataB>,
) -> F
where
	F: Field,
	P: PackedField<Scalar = F>,
	DataA: Deref<Target = [P]>,
	DataB: Deref<Target = [P]>,
{
	let n = a.len();
	a.as_ref()
		.par_iter()
		.zip_eq(b.as_ref().par_iter())
		.map(|(&a_i, &b_i)| a_i * b_i)
		.sum::<P>()
		.into_iter()
		.take(n)
		.sum()
}

#[inline]
pub fn inner_product_packed<F, P, DataA, DataB>(
	a: &FieldBuffer<P, DataA>,
	b: &FieldBuffer<P, DataB>,
) -> F
where
	F: Field,
	P: PackedField<Scalar = F>,
	DataA: Deref<Target = [P]>,
	DataB: Deref<Target = [P]>,
{
	let n = a.len();
	itertools::zip_eq(a.as_ref(), b.as_ref())
		.map(|(&a_i, &b_i)| a_i * b_i)
		.sum::<P>()
		.into_iter()
		.take(n)
		.sum()
}

#[cfg(test)]
mod tests {
	use binius_field::{PackedBinaryGhash4x128b, Random};
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	#[test]
	fn test_inner_product_packing_width_greater_than_buffer_length() {
		type P = PackedBinaryGhash4x128b;

		let mut rng = StdRng::seed_from_u64(0);

		// Create buffers with log_len = 0 (1 element), but packing width = 4
		let packed_a = P::random(&mut rng);
		let packed_b = P::random(&mut rng);

		let buffer_a = FieldBuffer::new(0, vec![packed_a]).unwrap();
		let buffer_b = FieldBuffer::new(0, vec![packed_b]).unwrap();

		// Compute inner product using both functions
		let result_par = inner_product_par(&buffer_a, &buffer_b);
		let result_packed = inner_product_packed(&buffer_a, &buffer_b);

		// Compute expected result manually - only first element should be used
		let expected = buffer_a.get(0).unwrap() * buffer_b.get(0).unwrap();

		assert_eq!(result_par, expected, "inner_product_par failed for log_len=0");
		assert_eq!(result_packed, expected, "inner_product_packed failed for log_len=0");
	}
}
