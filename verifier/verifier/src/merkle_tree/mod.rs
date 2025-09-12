// Copyright 2025 Irreducible Inc.
use std::{cmp::min, marker::PhantomData};

use binius_transcript::TranscriptReader;
use binius_utils::{DeserializeBytes, SerializeBytes};
use bytes::Buf;
use digest::{Digest, Output, OutputSizeUser, core_api::BlockSizeUser};

use crate::hash::{PseudoCompressionFunction, hash_serialize};

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
	#[error("the proof is invalid")]
	InvalidProof,
}

/// Provides the ability to read a merkle commitment and verify opening proofs against it.
///
/// This merkle tree implementation is special in the following ways:
/// - The outermost layer consists of hashes of **batches** of leaves, the batch size is determined
///   by `log_batch_size`.
/// - The innermost layer is _not_ the root; instead the tree is cut before it reaches the root, and
///   the innermost layer is `commit_layer`. This serves as the commitment.
///
/// Generics:
/// - `T`: The leaf type. (_Not_ the type of a leaf batch. A leaf batch is a slice of elements of
///   type `T`.)
/// - `H`: The hashing function used for hashing the leaf batches.
/// - `C`: The compression function used to construct inner nodes.
///
/// Usage:
/// - To read the commitment, use [`Self::read_commitment`].
/// - Then (later), to verify an opening proof (merkle path), use [`Self::verify_opening`].
pub struct MerkleTreeVerifier<T, H: OutputSizeUser, C> {
	/// The hashing algorithm used for hashing the leaves.
	digest: PhantomData<H>,
	/// The compression algorithm used for compressing two nodes into one.
	compression: C,
	/// The leaves are only stored in the prover. But we want to have the generic `T` on the
	/// verifier, which is why we need to add `PhantomData`.
	leaves: PhantomData<Vec<T>>,
	/// The committed layer of the merkle tree, which is read in [`Self::read_commitment`].
	commitment: Vec<Output<H>>,
	/// Base-2 logarithm of the batch size.
	log_batch_size: usize,
	/// Base-2 logarithm of the number of leaf batches. Equal to `log2(leaves.len()) -
	/// log_batch_size`.
	log_leaf_batches: usize,
	/// The index of the innermost layer, which is also the layer that is committed.
	/// `commit_layer = 0` means the innermost layer is the root layer (1 entry).
	/// In general the index of a layer is equal to `log2(num_nodes_in_layer)`.
	commit_layer: usize,
}

impl<T, H, C> MerkleTreeVerifier<T, H, C>
where
	T: DeserializeBytes + SerializeBytes,
	H: Digest + BlockSizeUser,
	C: PseudoCompressionFunction<Output<H>, 2>,
{
	/// Reads a merkle tree commitment. Returns a verifier instance which allows to verify openings
	/// using [`Self::verify_opening`].
	///
	/// Arguments:
	/// - `compression`: The compression function used to construct inner nodes.
	/// - `log_leaves`: Base-2 logarithm of the number of raw leaves. Note that a leaf batch (which
	///   is an "actual leaf of the tree") consists of a slice of leaves.
	/// - `log_batch_size`: Base-2 logarithm of the leaf batch size.
	/// - `commit_layer`: The index of the innermost layer, which is used as a commitment.
	///   `commit_layer = 0` means the innermost layer is the root layer (1 entry). In general the
	///   index of a layer is equal to `log2(num_nodes_in_layer)`.
	/// - `transcript`: The [`TranscriptReader`] used for reading the commitment.
	pub fn read_commitment(
		compression: C,
		log_leaves: usize,
		log_batch_size: usize,
		mut commit_layer: usize,
		transcript: &mut TranscriptReader<impl Buf>,
	) -> Self {
		let log_leaf_batches = log_leaves.checked_sub(log_batch_size).unwrap();

		// if commit_layer is bigger than tree depth, cut it down
		commit_layer = min(commit_layer, log_leaf_batches);

		// read committed layer with index `commit_layer` from `transcript`
		let commitment = transcript.read_vec(1 << commit_layer).unwrap();

		// return instance which can be used later for verifying openings
		Self {
			digest: PhantomData,
			compression,
			leaves: PhantomData,
			commitment,
			log_batch_size,
			log_leaf_batches,
			commit_layer,
		}
	}

	/// Verifies opening of a leaf batch.
	///
	/// Arguments:
	/// - `leaf_batch_index`: The index of the leaf batch whose opening proof should be verified.
	/// - `transcript`: The [`TranscriptReader`] which is used for reading the opening proof.
	pub fn verify_opening(
		&self,
		mut leaf_batch_index: usize,
		transcript: &mut TranscriptReader<impl Buf>,
	) -> Result<Vec<T>, VerificationError> {
		debug_assert_eq!(0, leaf_batch_index >> self.log_leaf_batches);

		// read leaf batch
		let leaf_batch = transcript.read_vec(1 << self.log_batch_size).unwrap();

		// hash leaf batch
		let mut leaf_digest = hash_serialize::<T, H>(&leaf_batch).unwrap();

		// read merkle path up to `self.commit_layer` and compress
		for _ in 0..(self.log_leaf_batches - self.commit_layer) {
			let sibling = transcript.read().unwrap();
			let pair = if leaf_batch_index & 1 == 0 {
				[leaf_digest, sibling]
			} else {
				[sibling, leaf_digest]
			};
			leaf_digest = self.compression.compress(pair);
			leaf_batch_index >>= 1;
		}

		// check that the resulting hash is indeed the one in the commitment
		match leaf_digest == self.commitment[leaf_batch_index] {
			true => Ok(leaf_batch),
			false => Err(VerificationError::InvalidProof),
		}
	}

	/// Number of leaf batches.
	pub fn log_leaf_batches(&self) -> usize {
		self.log_leaf_batches
	}
}
