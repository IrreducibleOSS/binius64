// Copyright 2025 Irreducible Inc.

use binius_field::PackedField;
use binius_math::FieldBuffer;

/// `MultilinearTriplet` holds three field buffers, corresponding to the
/// three shift variants. Every field buffer implicitly has
/// `log_len = 2 * LOG_WORD_SIZE_BITS`.
#[derive(Debug, Clone)]
pub struct MultilinearTriplet<P: PackedField> {
	pub sll: FieldBuffer<P>,
	pub srl: FieldBuffer<P>,
	pub sra: FieldBuffer<P>,
}
