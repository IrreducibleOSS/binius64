// Copyright 2025 Irreducible Inc.

use binius_field::{Field, PackedField};
use binius_frontend::word::Word;
use binius_math::FieldBuffer;
use binius_utils::checked_arithmetics::strict_log_2;
use binius_verifier::protocols::shift::{
	LOG_WORD_SIZE_BITS, WORD_SIZE_BITS, inner_product as inner_product_scalar,
	tensor_expand as tensor_expand_scalar,
};

// Not sure if this function should exist
// or there's a better way.
// Must return Result rather than using unwrap
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
