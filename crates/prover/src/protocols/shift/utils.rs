// Copyright 2025 Irreducible Inc.

use binius_field::{Field, PackedField};
use binius_math::FieldBuffer;
use binius_utils::checked_arithmetics::checked_log_2;
use tracing::instrument;

/// Converts a vector of field elements into a packed `FieldBuffer`.
///
/// Packs the field elements into `PackedField` elements by chunking them into
/// groups of `P::WIDTH`, then creates a `FieldBuffer` with the appropriate log length.
///
/// # Panics
///
/// Panics if `multilinear.len()` is not a power of 2, as required by `FieldBuffer`.
#[instrument(skip_all, name = "make_field_buffer")]
pub fn make_field_buffer<F: Field, P: PackedField<Scalar = F>>(
	multilinear: Vec<F>,
) -> FieldBuffer<P> {
	let packed_values = multilinear
		.chunks(P::WIDTH)
		.map(|chunk| P::from_scalars(chunk.iter().copied()))
		.collect();
	let log_len = checked_log_2(multilinear.len());
	FieldBuffer::new(log_len, packed_values).expect("multilinear has valid power-of-2 length")
}
