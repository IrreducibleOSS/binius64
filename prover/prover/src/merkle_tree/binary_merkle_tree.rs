// Copyright 2024-2025 Irreducible Inc.

use std::{fmt::Debug, mem::MaybeUninit};

use binius_field::Field;
use binius_utils::{
	checked_arithmetics::log2_strict_usize,
	mem::slice_assume_init_mut,
	rayon::{prelude::*, slice::ParallelSlice},
};
use binius_verifier::merkle_tree::Error;
use digest::{FixedOutputReset, Output, crypto_common::BlockSizeUser};

use crate::hash::{ParallelDigest, parallel_compression::ParallelPseudoCompression};

/// A binary Merkle tree that commits batches of vectors.
///
/// The vector entries at each index in a batch are hashed together into leaf digests. Then a
/// Merkle tree is constructed over the leaf digests. The implementation requires that the vector
/// lengths are all equal to each other and a power of two.
#[derive(Debug, Clone)]
pub struct BinaryMerkleTree<D> {
	/// Base-2 logarithm of the number of leaves
	pub log_len: usize,
	/// The inner nodes, arranged as a flattened array of layers with the root at the end
	pub inner_nodes: Vec<D>,
}

pub fn build<F, H, C>(
	compression: &C,
	elements: &[F],
	batch_size: usize,
) -> Result<BinaryMerkleTree<Output<H::Digest>>, Error>
where
	F: Field,
	H: ParallelDigest<Digest: BlockSizeUser + FixedOutputReset>,
	C: ParallelPseudoCompression<Output<H::Digest>, 2>,
{
	if !elements.len().is_multiple_of(batch_size) {
		return Err(Error::IncorrectBatchSize);
	}

	let len = elements.len() / batch_size;

	if !len.is_power_of_two() {
		return Err(Error::PowerOfTwoLengthRequired);
	}

	let log_len = log2_strict_usize(len);

	internal_build(
		compression,
		|inner_nodes| hash_interleaved::<_, H>(elements, inner_nodes),
		log_len,
	)
}

fn internal_build<Digest, C>(
	compression: &C,
	// Must either successfully initialize the passed in slice or return error
	hash_leaves: impl FnOnce(&mut [MaybeUninit<Digest>]),
	log_len: usize,
) -> Result<BinaryMerkleTree<Digest>, Error>
where
	Digest: Clone + Send + Sync,
	C: ParallelPseudoCompression<Digest, 2>,
{
	let total_length = (1 << (log_len + 1)) - 1;
	let mut inner_nodes = Vec::with_capacity(total_length);

	hash_leaves(&mut inner_nodes.spare_capacity_mut()[..(1 << log_len)]);

	let (prev_layer, mut remaining) = inner_nodes.spare_capacity_mut().split_at_mut(1 << log_len);

	let mut prev_layer = unsafe {
		// SAFETY: prev-layer was initialized by hash_leaves
		slice_assume_init_mut(prev_layer)
	};
	for i in 1..(log_len + 1) {
		let (next_layer, next_remaining) = remaining.split_at_mut(1 << (log_len - i));
		remaining = next_remaining;

		compress_layer(compression, prev_layer, next_layer);

		prev_layer = unsafe {
			// SAFETY: next_layer was just initialized by compress_layer
			slice_assume_init_mut(next_layer)
		};
	}

	unsafe {
		// SAFETY: inner_nodes should be entirely initialized by now
		// Note that we don't incrementally update inner_nodes.len() since
		// that doesn't play well with using split_at_mut on spare capacity.
		inner_nodes.set_len(total_length);
	}
	Ok(BinaryMerkleTree {
		log_len,
		inner_nodes,
	})
}

pub fn build_from_iterator<F, H, C, ParIter>(
	compression: &C,
	iterated_chunks: ParIter,
	log_len: usize,
) -> Result<BinaryMerkleTree<Output<H::Digest>>, Error>
where
	F: Field,
	H: ParallelDigest<Digest: BlockSizeUser + FixedOutputReset>,
	C: ParallelPseudoCompression<Output<H::Digest>, 2>,
	ParIter: IndexedParallelIterator<Item: IntoIterator<Item = F>>,
{
	internal_build(
		compression,
		|inner_nodes| hash_iterated::<F, H, _>(iterated_chunks, inner_nodes),
		log_len,
	)
}

impl<D: Clone> BinaryMerkleTree<D> {
	pub fn root(&self) -> D {
		self.inner_nodes
			.last()
			.expect("MerkleTree inner nodes can't be empty")
			.clone()
	}

	pub fn layer(&self, layer_depth: usize) -> Result<&[D], Error> {
		if layer_depth > self.log_len {
			return Err(Error::IncorrectLayerDepth);
		}
		let range_start = self.inner_nodes.len() + 1 - (1 << (layer_depth + 1));

		Ok(&self.inner_nodes[range_start..range_start + (1 << layer_depth)])
	}

	/// Get a Merkle branch for the given index
	///
	/// Throws if the index is out of range
	pub fn branch(&self, index: usize, layer_depth: usize) -> Result<Vec<D>, Error> {
		if index >= 1 << self.log_len || layer_depth > self.log_len {
			return Err(Error::IndexOutOfRange {
				max: (1 << self.log_len) - 1,
			});
		}

		let branch = (0..self.log_len - layer_depth)
			.map(|j| {
				let node_index = (((1 << j) - 1) << (self.log_len + 1 - j)) | (index >> j) ^ 1;
				self.inner_nodes[node_index].clone()
			})
			.collect();

		Ok(branch)
	}
}

#[tracing::instrument("MerkleTree::compress_layer", skip_all, level = "debug")]
fn compress_layer<D, C>(compression: &C, prev_layer: &[D], next_layer: &mut [MaybeUninit<D>])
where
	D: Clone + Send + Sync,
	C: ParallelPseudoCompression<D, 2>,
{
	compression.parallel_compress(prev_layer, next_layer);
}

/// Hashes the elements in chunks of a vector into digests.
///
/// Given a vector of elements and an output buffer of N hash digests, this splits the elements
/// into N equal-sized chunks and hashes each chunks into the corresponding output digest. This
/// returns the number of elements hashed into each digest.
#[tracing::instrument("hash_interleaved", skip_all, level = "debug")]
fn hash_interleaved<F, H>(elems: &[F], digests: &mut [MaybeUninit<Output<H::Digest>>])
where
	F: Field,
	H: ParallelDigest<Digest: BlockSizeUser + FixedOutputReset>,
{
	assert!(elems.len().is_multiple_of(digests.len())); // pre-condition

	let hash_data_iter = elems
		.par_chunks(elems.len() / digests.len())
		.map(|s| s.iter().copied());
	hash_iterated::<_, H, _>(hash_data_iter, digests);
}

fn hash_iterated<F, H, ParIter>(
	iterated_chunks: ParIter,
	digests: &mut [MaybeUninit<Output<H::Digest>>],
) where
	F: Field,
	H: ParallelDigest<Digest: BlockSizeUser + FixedOutputReset>,
	ParIter: IndexedParallelIterator<Item: IntoIterator<Item = F>>,
{
	assert_eq!(iterated_chunks.len(), digests.len());

	let hasher = H::new();
	hasher.digest(iterated_chunks, digests);
}
