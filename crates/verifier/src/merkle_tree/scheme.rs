// Copyright 2024-2025 Irreducible Inc.

use std::{array, fmt::Debug, marker::PhantomData};

use binius_field::Field;
use binius_transcript::{Buf, TranscriptReader};
use binius_utils::{
	bail,
	checked_arithmetics::{log2_ceil_usize, log2_strict_usize},
};
use digest::{Digest, Output, core_api::BlockSizeUser};
use getset::Getters;

use super::{
	error::{Error, VerificationError},
	merkle_tree_vcs::MerkleTreeScheme,
};
use crate::hash::{PseudoCompressionFunction, hash_serialize};

#[derive(Debug, Clone, Getters)]
pub struct BinaryMerkleTreeScheme<T, H, C> {
	#[getset(get = "pub")]
	compression: C,
	// This makes it so that `BinaryMerkleTreeScheme` remains Send + Sync
	// See https://doc.rust-lang.org/nomicon/phantom-data.html#table-of-phantomdata-patterns
	_phantom: PhantomData<fn() -> (T, H)>,
}

impl<T, H, C> BinaryMerkleTreeScheme<T, H, C> {
	pub fn new(compression: C) -> Self {
		Self {
			compression,
			_phantom: PhantomData,
		}
	}
}

impl<F, H, C> MerkleTreeScheme<F> for BinaryMerkleTreeScheme<F, H, C>
where
	F: Field,
	H: Digest + BlockSizeUser,
	// TODO: Remove Sync trait here
	C: PseudoCompressionFunction<Output<H>, 2>,
{
	type Digest = Output<H>;

	/// This layer allows minimizing the proof size.
	fn optimal_verify_layer(&self, n_queries: usize, tree_depth: usize) -> usize {
		log2_ceil_usize(n_queries).min(tree_depth)
	}

	fn proof_size(&self, len: usize, n_queries: usize, layer_depth: usize) -> Result<usize, Error> {
		if !len.is_power_of_two() {
			bail!(Error::PowerOfTwoLengthRequired)
		}

		let log_len = log2_strict_usize(len);

		if layer_depth > log_len {
			bail!(Error::IncorrectLayerDepth)
		}

		Ok(((log_len - layer_depth - 1) * n_queries + (1 << layer_depth))
			* <H as Digest>::output_size())
	}

	fn verify_vector(
		&self,
		root: &Self::Digest,
		data: &[F],
		batch_size: usize,
	) -> Result<(), Error> {
		if !data.len().is_multiple_of(batch_size) {
			bail!(Error::IncorrectBatchSize);
		}

		let mut digests = data
			.chunks(batch_size)
			.map(|chunk| {
				hash_serialize::<F, H>(chunk)
					.expect("values are of TowerField type which we expect to be serializable")
			})
			.collect::<Vec<_>>();

		fold_digests_vector_inplace(&self.compression, &mut digests)?;
		if digests[0] != *root {
			bail!(VerificationError::InvalidProof)
		}
		Ok(())
	}

	fn verify_layer(
		&self,
		root: &Self::Digest,
		layer_depth: usize,
		layer_digests: &[Self::Digest],
	) -> Result<(), Error> {
		if 1 << layer_depth != layer_digests.len() {
			bail!(VerificationError::IncorrectVectorLength)
		}

		let mut digests = layer_digests.to_owned();

		fold_digests_vector_inplace(&self.compression, &mut digests)?;

		if digests[0] != *root {
			bail!(VerificationError::InvalidProof)
		}
		Ok(())
	}

	fn verify_opening<B: Buf>(
		&self,
		mut index: usize,
		values: &[F],
		layer_depth: usize,
		tree_depth: usize,
		layer_digests: &[Self::Digest],
		proof: &mut TranscriptReader<B>,
	) -> Result<(), Error> {
		if (1 << layer_depth) != layer_digests.len() {
			bail!(VerificationError::IncorrectVectorLength);
		}

		if index >= (1 << tree_depth) {
			bail!(Error::IndexOutOfRange {
				max: (1 << tree_depth) - 1
			});
		}

		let mut leaf_digest = hash_serialize::<F, H>(values)
			.expect("values are of TowerField type which we expect to be serializable");
		for branch_node in proof.read_vec(tree_depth - layer_depth)? {
			leaf_digest = self.compression.compress(if index & 1 == 0 {
				[leaf_digest, branch_node]
			} else {
				[branch_node, leaf_digest]
			});
			index >>= 1;
		}

		(leaf_digest == layer_digests[index])
			.then_some(())
			.ok_or_else(|| VerificationError::InvalidProof.into())
	}
}

// Merkle-tree-like folding
fn fold_digests_vector_inplace<C, D>(compression: &C, digests: &mut [D]) -> Result<(), Error>
where
	C: PseudoCompressionFunction<D, 2>,
	D: Clone + Default + Send + Sync + Debug,
{
	if !digests.len().is_power_of_two() {
		bail!(Error::PowerOfTwoLengthRequired);
	}

	let mut len = digests.len() / 2;

	while len != 0 {
		for i in 0..len {
			digests[i] = compression.compress(array::from_fn(|j| digests[2 * i + j].clone()));
		}
		len /= 2;
	}

	Ok(())
}
