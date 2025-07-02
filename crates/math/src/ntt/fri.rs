// Copyright 2024-2025 Irreducible Inc.

use std::iter;

use binius_field::{BinaryField, ExtensionField, PackedField};
use crate::{MultilinearQuery, extrapolate_line_scalar};
use binius_maybe_rayon::prelude::*;
use bytemuck::zeroed_vec;
use tracing::instrument;

use crate::AdditiveNTT;

/// FRI-fold the interleaved codeword using the given challenges.
///
/// ## Arguments
///
/// * `math` - the NTT instance, used to look up the twiddle values.
/// * `codeword` - an interleaved codeword.
/// * `challenges` - the folding challenges. The length must be at least `log_batch_size`.
/// * `log_len` - the binary logarithm of the code length.
/// * `log_batch_size` - the binary logarithm of the interleaved code batch size.
///
/// See [DP24], Def. 3.6 and Lemma 3.9 for more details.
///
/// [DP24]: <https://eprint.iacr.org/2024/504>
#[instrument(skip_all, level = "debug")]
pub fn fold_interleaved_allocated<F, FS, NTT, P>(
	ntt: &NTT,
	codeword: &[P],
	challenges: &[F],
	log_len: usize,
	log_batch_size: usize,
	out: &mut [F],
) where
	F: BinaryField + ExtensionField<FS>,
	FS: BinaryField,
	NTT: AdditiveNTT<FS> + Sync,
	P: PackedField<Scalar = F>,
{
	assert_eq!(codeword.len(), 1 << (log_len + log_batch_size).saturating_sub(P::LOG_WIDTH));
	assert!(challenges.len() >= log_batch_size);
	assert_eq!(out.len(), 1 << (log_len - (challenges.len() - log_batch_size)));

	let (interleave_challenges, fold_challenges) = challenges.split_at(log_batch_size);
	let tensor = MultilinearQuery::expand(interleave_challenges);

	// For each chunk of size `2^chunk_size` in the codeword, fold it with the folding challenges
	let fold_chunk_size = 1 << fold_challenges.len();
	let chunk_size = 1 << challenges.len().saturating_sub(P::LOG_WIDTH);
	codeword
		.par_chunks(chunk_size)
		.enumerate()
		.zip(out)
		.for_each_init(
			|| vec![F::default(); fold_chunk_size],
			|scratch_buffer, ((i, chunk), out)| {
				*out = fold_interleaved_chunk(
					ntt,
					log_len,
					log_batch_size,
					i,
					chunk,
					tensor.expansion(),
					fold_challenges,
					scratch_buffer,
				)
			},
		)
}

pub fn fold_interleaved<F, FS, NTT, P>(
	ntt: &NTT,
	codeword: &[P],
	challenges: &[F],
	log_len: usize,
	log_batch_size: usize,
) -> Vec<F>
where
	F: BinaryField + ExtensionField<FS>,
	FS: BinaryField,
	NTT: AdditiveNTT<FS> + Sync,
	P: PackedField<Scalar = F>,
{
	let mut result =
		zeroed_vec(1 << log_len.saturating_sub(challenges.len().saturating_sub(log_batch_size)));
	fold_interleaved_allocated(ntt, codeword, challenges, log_len, log_batch_size, &mut result);
	result
}

/// Calculate fold of `values` at `index` with `r` random coefficient.
///
/// See [DP24], Def. 3.6.
///
/// [DP24]: <https://eprint.iacr.org/2024/504>
#[inline]
fn fold_pair<F, FS, NTT>(ntt: &NTT, round: usize, index: usize, values: (F, F), r: F) -> F
where
	F: BinaryField + ExtensionField<FS>,
	FS: BinaryField,
	NTT: AdditiveNTT<FS>,
{
	// Perform inverse additive NTT butterfly
	let t = ntt.get_subspace_eval(round, index);
	let (mut u, mut v) = values;
	v += u;
	u += v * t;
	extrapolate_line_scalar(u, v, r)
}

/// Calculate FRI fold of `values` at a `chunk_index` with random folding challenges.
///
/// Folds a coset of a Reed–Solomon codeword into a single value using the FRI folding algorithm.
/// The coset has size $2^n$, where $n$ is the number of challenges.
///
/// See [DP24], Def. 3.6 and Lemma 3.9 for more details.
///
/// NB: This method is on a hot path and does not perform any allocations or
/// precondition checks.
///
/// ## Arguments
///
/// * `math` - the NTT instance, used to look up the twiddle values.
/// * `log_len` - the binary logarithm of the code length.
/// * `chunk_index` - the index of the chunk, of size $2^n$, in the full codeword.
/// * `values` - mutable slice of values to fold, modified in place.
/// * `challenges` - the sequence of folding challenges, with length $n$.
///
/// ## Pre-conditions
///
/// - `challenges.len() <= log_len`.
/// - `log_len <= math.log_domain_size()`, so that the NTT domain is large enough.
/// - `values.len() == 1 << challenges.len()`.
///
/// [DP24]: <https://eprint.iacr.org/2024/504>
#[inline]
pub fn fold_chunk<F, FS, NTT>(
	ntt: &NTT,
	mut log_len: usize,
	chunk_index: usize,
	values: &mut [F],
	challenges: &[F],
) -> F
where
	F: BinaryField + ExtensionField<FS>,
	FS: BinaryField,
	NTT: AdditiveNTT<FS>,
{
	let mut log_size = challenges.len();

	// Preconditions
	debug_assert!(log_size <= log_len);
	debug_assert!(log_len <= ntt.log_domain_size());
	debug_assert_eq!(values.len(), 1 << log_size);

	// FRI-fold the values in place.
	for &challenge in challenges {
		// Fold the (2i) and (2i+1)th cells of the scratch buffer in-place into the i-th cell
		for index_offset in 0..1 << (log_size - 1) {
			let pair = (values[index_offset << 1], values[(index_offset << 1) | 1]);
			values[index_offset] = fold_pair(
				ntt,
				log_len,
				(chunk_index << (log_size - 1)) | index_offset,
				pair,
				challenge,
			)
		}

		log_len -= 1;
		log_size -= 1;
	}

	values[0]
}

/// Calculate the fold of an interleaved chunk of values with random folding challenges.
///
/// The elements in the `values` vector are the interleaved cosets of a batch of codewords at the
/// index `coset_index`. That is, the layout of elements in the values slice is
///
/// ```text
/// [a0, b0, c0, d0, a1, b1, c1, d1, ...]
/// ```
///
/// where `a0, a1, ...` form a coset of a codeword `a`, `b0, b1, ...` form a coset of a codeword
/// `b`, and similarly for `c` and `d`.
///
/// The fold operation first folds the adjacent symbols in the slice using regular multilinear
/// tensor folding for the symbols from different cosets and FRI folding for the cosets themselves
/// using the remaining challenges.
//
/// NB: This method is on a hot path and does not perform any allocations or
/// precondition checks.
///
/// See [DP24], Def. 3.6 and Lemma 3.9 for more details.
///
/// [DP24]: <https://eprint.iacr.org/2024/504>
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn fold_interleaved_chunk<F, FS, P, NTT>(
	ntt: &NTT,
	log_len: usize,
	log_batch_size: usize,
	chunk_index: usize,
	values: &[P],
	tensor: &[P],
	fold_challenges: &[F],
	scratch_buffer: &mut [F],
) -> F
where
	F: BinaryField + ExtensionField<FS>,
	FS: BinaryField,
	NTT: AdditiveNTT<FS>,
	P: PackedField<Scalar = F>,
{
	// Preconditions
	debug_assert!(fold_challenges.len() <= log_len);
	debug_assert!(log_len <= ntt.log_domain_size());
	debug_assert_eq!(
		values.len(),
		1 << (fold_challenges.len() + log_batch_size).saturating_sub(P::LOG_WIDTH)
	);
	debug_assert_eq!(tensor.len(), 1 << log_batch_size.saturating_sub(P::LOG_WIDTH));
	debug_assert!(scratch_buffer.len() >= 1 << fold_challenges.len());

	let scratch_buffer = &mut scratch_buffer[..1 << fold_challenges.len()];

	if log_batch_size == 0 {
		iter::zip(&mut *scratch_buffer, P::iter_slice(values)).for_each(|(dst, val)| *dst = val);
	} else {
		let folded_values = values
			.chunks(1 << (log_batch_size - P::LOG_WIDTH))
			.map(|chunk| {
				iter::zip(chunk, tensor)
					.map(|(&a_i, &b_i)| a_i * b_i)
					.sum::<P>()
					.into_iter()
					.take(1 << log_batch_size)
					.sum()
			});
		iter::zip(&mut *scratch_buffer, folded_values).for_each(|(dst, val)| *dst = val);
	};

	fold_chunk(ntt, log_len, chunk_index, scratch_buffer, fold_challenges)
}
