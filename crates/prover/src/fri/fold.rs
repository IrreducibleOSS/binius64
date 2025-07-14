// Copyright 2024-2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, PackedField};
use binius_math::{multilinear::eq::eq_ind_partial_eval, ntt::AdditiveNTT};
use binius_maybe_rayon::prelude::*;
use binius_verifier::fri::fold::fold_interleaved_chunk;
use bytemuck::zeroed_vec;
use tracing::instrument;

/// FRI-fold the interleaved codeword using the given challenges.
///
/// ## Arguments
///
/// * `ntt` - the NTT instance, used to look up the twiddle values.
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
	let tensor = eq_ind_partial_eval(interleave_challenges);

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
					tensor.as_ref(),
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
