use binius_field::{BinaryField, PackedExtension, PackedField};
use binius_math::{ReedSolomonCode, ntt::AdditiveNTT};
use binius_maybe_rayon::prelude::*;
use binius_utils::bail;
use binius_verifier::{fri::FRIParams, merkle_tree::MerkleTreeScheme};
use bytemuck::zeroed_vec;
use tracing::instrument;

use super::{
	error::Error,
	logging::{MerkleTreeDimensionData, RSEncodeDimensionData, SortAndMergeDimensionData},
};
use crate::merkle_tree::MerkleTreeProver;

#[derive(Debug)]
pub struct CommitOutput<P, VCSCommitment, VCSCommitted> {
	pub commitment: VCSCommitment,
	pub committed: VCSCommitted,
	pub codeword: Vec<P>,
}

/// Encodes and commits the input message.
///
/// ## Arguments
///
/// * `rs_code` - the Reed-Solomon code to use for encoding
/// * `params` - common FRI protocol parameters.
/// * `merkle_prover` - the merke tree prover to use for committing
/// * `message` - the interleaved message to encode and commit
#[instrument(skip_all, level = "debug")]
pub fn commit_interleaved<F, FA, P, PA, NTT, MerkleProver, VCS>(
	rs_code: &ReedSolomonCode<FA>,
	params: &FRIParams<F, FA>,
	ntt: &NTT,
	merkle_prover: &MerkleProver,
	message: &[P],
) -> Result<CommitOutput<P, VCS::Digest, MerkleProver::Committed>, Error>
where
	F: BinaryField,
	FA: BinaryField,
	P: PackedField<Scalar = F> + PackedExtension<FA, PackedSubfield = PA>,
	PA: PackedField<Scalar = FA>,
	NTT: AdditiveNTT<FA> + Sync,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	let n_elems = rs_code.dim() << params.log_batch_size();
	if message.len() * P::WIDTH != n_elems {
		bail!(Error::InvalidArgs(
			"interleaved message length does not match code parameters".to_string()
		));
	}

	commit_interleaved_with(params, ntt, merkle_prover, move |buffer| {
		buffer.copy_from_slice(message)
	})
}

/// Encodes and commits the input message with a closure for writing the message.
///
/// ## Arguments
///
/// * `rs_code` - the Reed-Solomon code to use for encoding
/// * `params` - common FRI protocol parameters.
/// * `merkle_prover` - the Merkle tree prover to use for committing
/// * `message_writer` - a closure that writes the interleaved message to encode and commit
pub fn commit_interleaved_with<F, FA, P, PA, NTT, MerkleProver, VCS>(
	params: &FRIParams<F, FA>,
	ntt: &NTT,
	merkle_prover: &MerkleProver,
	message_writer: impl FnOnce(&mut [P]),
) -> Result<CommitOutput<P, VCS::Digest, MerkleProver::Committed>, Error>
where
	F: BinaryField,
	FA: BinaryField,
	P: PackedField<Scalar = F> + PackedExtension<FA, PackedSubfield = PA>,
	PA: PackedField<Scalar = FA>,
	NTT: AdditiveNTT<FA> + Sync,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	let rs_code = params.rs_code();
	let log_batch_size = params.log_batch_size();
	let log_elems = rs_code.log_dim() + log_batch_size;
	if log_elems < P::LOG_WIDTH {
		todo!("can't handle this case well");
	}

	let mut encoded = zeroed_vec(1 << (log_elems - P::LOG_WIDTH + rs_code.log_inv_rate()));

	let dimensions_data = SortAndMergeDimensionData::new::<F>(log_elems);
	tracing::debug_span!(
		"[task] Sort & Merge",
		phase = "commit",
		perfetto_category = "task.main",
		?dimensions_data
	)
	.in_scope(|| {
		message_writer(&mut encoded[..1 << (log_elems - P::LOG_WIDTH)]);
	});

	let dimensions_data = RSEncodeDimensionData::new::<F>(log_elems, log_batch_size);
	tracing::debug_span!(
		"[task] RS Encode",
		phase = "commit",
		perfetto_category = "task.main",
		?dimensions_data
	)
	.in_scope(|| rs_code.encode_ext_batch_inplace(ntt, &mut encoded, log_batch_size))?;

	// Take the first arity as coset_log_len, or use the value such that the number of leaves equals
	// 1 << log_inv_rate if arities is empty
	let coset_log_len = params.fold_arities().first().copied().unwrap_or(log_elems);

	let log_len = params.log_len() - coset_log_len;
	let dimension_data = MerkleTreeDimensionData::new::<F>(log_len, 1 << coset_log_len);
	let merkle_tree_span = tracing::debug_span!(
		"[task] Merkle Tree",
		phase = "commit",
		perfetto_category = "task.main",
		dimensions_data = ?dimension_data
	)
	.entered();
	let (commitment, vcs_committed) = if coset_log_len > P::LOG_WIDTH {
		let iterated_big_chunks = to_par_scalar_big_chunks(&encoded, 1 << coset_log_len);
		merkle_prover.commit_iterated(iterated_big_chunks, log_len)?
	} else {
		let iterated_small_chunks = to_par_scalar_small_chunks(&encoded, 1 << coset_log_len);
		merkle_prover.commit_iterated(iterated_small_chunks, log_len)?
	};
	drop(merkle_tree_span);

	Ok(CommitOutput {
		commitment: commitment.root,
		committed: vcs_committed,
		codeword: encoded,
	})
}

/// Creates a parallel iterator over scalars of subfield elementsAssumes chunk_size to be a power of
/// two
fn to_par_scalar_big_chunks<P>(
	packed_slice: &[P],
	chunk_size: usize,
) -> impl IndexedParallelIterator<Item: Iterator<Item = P::Scalar> + Send + '_>
where
	P: PackedField,
{
	packed_slice
		.par_chunks(chunk_size / P::WIDTH)
		.map(|chunk| PackedField::iter_slice(chunk))
}

fn to_par_scalar_small_chunks<P>(
	packed_slice: &[P],
	chunk_size: usize,
) -> impl IndexedParallelIterator<Item: Iterator<Item = P::Scalar> + Send + '_>
where
	P: PackedField,
{
	(0..packed_slice.len() * P::WIDTH)
		.into_par_iter()
		.step_by(chunk_size)
		.map(move |start_index| {
			let packed_item = &packed_slice[start_index / P::WIDTH];
			packed_item
				.iter()
				.skip(start_index % P::WIDTH)
				.take(chunk_size)
		})
}

#[cfg(test)]
mod tests {
	use binius_field::{
		BinaryField16b, PackedBinaryField4x16b, PackedBinaryField16x16b, PackedField,
	};

	use super::*;

	#[test]
	fn test_parallel_iterator() {
		// Compare results for small and large chunk sizes to ensure that they're identical
		let data: Vec<_> = (0..64).map(BinaryField16b::from).collect();

		let mut data_packed_4 = vec![];

		for i in 0..64 / 4 {
			let mut scalars = vec![];
			for j in 0..4 {
				scalars.push(data[4 * i + j]);
			}

			data_packed_4.push(PackedBinaryField4x16b::from_scalars(scalars.into_iter()));
		}

		let mut data_packed_16 = vec![];

		for i in 0..64 / 16 {
			let mut scalars = vec![];
			for j in 0..16 {
				scalars.push(data[16 * i + j]);
			}

			data_packed_16.push(PackedBinaryField16x16b::from_scalars(scalars.into_iter()));
		}

		let packing_smaller_than_chunk = to_par_scalar_big_chunks(&data_packed_4, 8);

		let packing_bigger_than_chunk = to_par_scalar_small_chunks(&data_packed_16, 8);

		let collected_smaller: Vec<_> = packing_smaller_than_chunk
			.map(|inner| {
				let result: Vec<_> = inner.collect();
				result
			})
			.collect();

		let collected_bigger: Vec<_> = packing_bigger_than_chunk
			.map(|inner| {
				let result: Vec<_> = inner.collect();
				result
			})
			.collect();

		assert_eq!(collected_smaller, collected_bigger);
	}
}
