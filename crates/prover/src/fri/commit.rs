use binius_field::{BinaryField, PackedExtension, PackedField};
use binius_math::{FieldSlice, ntt::AdditiveNTT};
use binius_utils::{bail, rayon::prelude::*};
use binius_verifier::{fri::FRIParams, merkle_tree::MerkleTreeScheme};
use bytemuck::zeroed_vec;

use super::error::Error;
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
pub fn commit_interleaved<F, FA, P, PA, NTT, MerkleProver, VCS>(
	params: &FRIParams<F, FA>,
	ntt: &NTT,
	merkle_prover: &MerkleProver,
	message: FieldSlice<P>,
) -> Result<CommitOutput<P, VCS::Digest, MerkleProver::Committed>, Error>
where
	F: BinaryField,
	FA: BinaryField,
	P: PackedField<Scalar = F> + PackedExtension<FA, PackedSubfield = PA>,
	PA: PackedField<Scalar = FA>,
	NTT: AdditiveNTT<Field = FA> + Sync,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	if message.log_len() != params.log_msg_len() {
		bail!(Error::InvalidArgs(
			"interleaved message length does not match code parameters".to_string()
		));
	}

	commit_interleaved_with(params, ntt, merkle_prover, move |buffer| {
		buffer.copy_from_slice(message.as_ref())
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
fn commit_interleaved_with<F, FA, P, PA, NTT, MerkleProver, VCS>(
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
	NTT: AdditiveNTT<Field = FA> + Sync,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	let rs_code = params.rs_code();
	let log_batch_size = params.log_batch_size();
	let log_elems = rs_code.log_dim() + log_batch_size;
	if log_elems < P::LOG_WIDTH {
		todo!("can't handle this case well");
	}

	let _scope = tracing::debug_span!(
		"FRI Commit",
		log_batch_size,
		log_dim = rs_code.log_dim(),
		log_inv_rate = rs_code.log_inv_rate(),
		field_bits = F::N_BITS,
	)
	.entered();

	let mut encoded = zeroed_vec(1 << (log_elems - P::LOG_WIDTH + rs_code.log_inv_rate()));
	message_writer(&mut encoded[..1 << (log_elems - P::LOG_WIDTH)]);

	tracing::debug_span!("Reed–Solomon Encode")
		.in_scope(|| rs_code.encode_ext_batch_inplace(ntt, &mut encoded, log_batch_size))?;

	// Take the first arity as coset_log_len, or use the value such that the number of leaves equals
	// 1 << log_inv_rate if arities is empty
	let coset_log_len = params.fold_arities().first().copied().unwrap_or(log_elems);

	let log_len = params.log_len() - coset_log_len;
	let merkle_tree_span = tracing::debug_span!("Merkle Tree").entered();
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
	use binius_field::{PackedBinaryGhash2x128b, PackedBinaryGhash4x128b};
	use binius_math::{FieldBuffer, test_utils::random_scalars};
	use binius_verifier::config::B128;
	use rand::{prelude::*, rngs::StdRng};

	use super::*;

	#[test]
	fn test_parallel_iterator() {
		let mut rng = StdRng::seed_from_u64(0);

		// Compare results for small and large chunk sizes to ensure that they're identical
		let data = random_scalars::<B128>(&mut rng, 64);

		let data_packed_2 = FieldBuffer::<PackedBinaryGhash2x128b, _>::from_values(&data).unwrap();
		let data_packed_4 = FieldBuffer::<PackedBinaryGhash4x128b, _>::from_values(&data).unwrap();

		let packing_smaller_than_chunk = to_par_scalar_big_chunks(data_packed_2.as_ref(), 2);
		let packing_bigger_than_chunk = to_par_scalar_small_chunks(data_packed_4.as_ref(), 2);

		let collected_smaller: Vec<_> = packing_smaller_than_chunk
			.map(|inner| inner.collect::<Vec<_>>())
			.collect();
		let collected_bigger: Vec<_> = packing_bigger_than_chunk
			.map(|inner| inner.collect::<Vec<_>>())
			.collect();
		assert_eq!(collected_smaller, collected_bigger);
	}
}
