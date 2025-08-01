// Copyright 2025 Irreducible Inc.

use binius_field::{Field, PackedField};
use binius_frontend::word::Word;
use binius_math::FieldBuffer;
use binius_utils::{checked_arithmetics::strict_log_2, rayon::prelude::*};
use binius_verifier::{
	config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	protocols::shift::inner_product as inner_product_scalar,
};
use tracing::instrument;

#[instrument(skip_all, name = "tensor_expand_scalar")]
pub fn tensor_expand_scalar<F: Field>(x: &[F], n_vars: usize) -> Vec<F> {
	let mut result = vec![F::ONE; 1 << n_vars];

	for i in 0..n_vars {
		let (lower, upper) = result.split_at_mut(1 << i);
		lower
			.par_iter_mut()
			.zip(upper.par_iter_mut())
			.for_each(|(lo, hi)| {
				*hi = *lo * x[i];
				*lo -= *hi;
			});
	}

	result
}

// Not sure if this function should exist
// or there's a better way.
// Must return Result rather than using unwrap
#[instrument(skip_all, name = "make_field_buffer")]
pub fn make_field_buffer<F: Field, P: PackedField<Scalar = F>>(
	multilinear: Vec<F>,
) -> FieldBuffer<P> {
	let packed_values = multilinear
		.chunks(P::WIDTH)
		.map(|chunk| P::from_scalars(chunk.iter().copied()))
		.collect();
	let log_len = strict_log_2(multilinear.len()).unwrap() as usize;
	FieldBuffer::new(log_len, packed_values).expect("multilinear has valid power-of-2 length")
}

/// Compute inner product of tensor with all bits from words
pub fn naive_witness_evaluation<F: Field>(words: &[Word], challenges: &[F]) -> F {
	assert_eq!(strict_log_2(words.len()).unwrap() + LOG_WORD_SIZE_BITS, challenges.len());
	let tensor = tensor_expand_scalar(challenges, challenges.len());

	// Extract all bits from all words
	let all_bits: Vec<F> = words
		.iter()
		.flat_map(|word| {
			(0..WORD_SIZE_BITS).map(move |bit_idx| {
				if (*word >> bit_idx as u32) & Word::ONE == Word::ONE {
					F::ONE
				} else {
					F::ZERO
				}
			})
		})
		.collect();

	inner_product_scalar(&all_bits, &tensor)
}
