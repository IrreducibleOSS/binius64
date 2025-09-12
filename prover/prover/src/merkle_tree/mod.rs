// Copyright 2025 Irreducible Inc.
use std::{cmp::min, marker::PhantomData};

use binius_field::BinaryField;
use binius_transcript::TranscriptWriter;
use binius_utils::{SerializeBytes, checked_arithmetics::log2_strict_usize, rayon::prelude::*};
use binius_verifier::hash::{PseudoCompressionFunction, hash_serialize};
#[allow(unused_imports)]
use binius_verifier::merkle_tree::MerkleTreeVerifier;
use bytes::BufMut;
use digest::{Digest, Output, OutputSizeUser, core_api::BlockSizeUser};

/// Provides the ability to construct a merkle tree, commit to the root, and later prove openings.
///
/// See [`MerkleTreeVerifier`] for information about the structure of the merkle tree and the
/// generic types. Also note that the prover consumes the `leaves`, i.e., it owns them.
///
/// Usage:
/// - To construct the merkle tree and commit to it, use [`Self::write_commitment`]. \ This can be
///   read by the verifier using [`MerkleTreeVerifier::read_commitment`].
/// - Then (later), to construct an opening proof (merkle path), use [`Self::prove_opening`]. \ This
///   can be checked by the verifier using [`MerkleTreeVerifier::verify_opening`].
pub struct MerkleTreeProver<T, H: OutputSizeUser, C> {
	/// The hashing algorithm used for hashing the leaves.
	digest: PhantomData<H>,
	/// The compression algorithm used for compressing two nodes into one.
	compression: PhantomData<C>,
	/// The leaves. A leaf batch (which is an "actual leaf of the tree") consists of a slice of
	/// leaves.
	leaves: Vec<T>,
	/// The inner nodes of the merkle tree. Arranged as a `Vec` of layers, where each layer is a
	/// `Vec` of hashes. `nodes[0]` stores the outermost layer (the hashes of the leaf batches),
	/// and `nodes[nodes.len() - 1]` stores the innermost layer, determined by `commit_layer`.
	nodes: Vec<Vec<Output<H>>>,
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

impl<T, H, C> MerkleTreeProver<T, H, C>
where
	T: SerializeBytes + Sync,
	H: Digest + BlockSizeUser,
	C: PseudoCompressionFunction<Output<H>, 2> + Sync,
{
	/// Constructs a merkle tree and commits to it. Returns a prover instance which allows to prove
	/// openings using [`Self::prove_opening`].
	///
	/// The counterpart on the verifier side is [`MerkleTreeVerifier::read_commitment`].
	///
	/// Arguments:
	/// - `compression`: The compression function used to construct inner nodes.
	/// - `leaves`: The raw leaves. A leaf batch (which is an "actual leaf of the tree") consists of
	///   a slice of leaves.
	/// - `log_batch_size`: Base-2 logarithm of the leaf batch size.
	/// - `commit_layer`: The index of the innermost layer, which is used as a commitment.
	///   `commit_layer = 0` means the innermost layer is the root layer (1 entry). In general the
	///   index of a layer is equal to `log2(num_nodes_in_layer)`.
	/// - `transcript`: The [`TranscriptWriter`] used for writing the commitment.
	pub fn write_commitment(
		compression: C,
		leaves: Vec<T>,
		log_batch_size: usize,
		mut commit_layer: usize,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) -> Self {
		let log_leaves = log2_strict_usize(leaves.len());
		let log_leaf_batches = log_leaves.checked_sub(log_batch_size).unwrap();

		// if commit_layer is bigger than tree depth, cut it down
		commit_layer = min(commit_layer, log_leaf_batches);

		// hash the leaves
		let mut leaf_batch_digests: Vec<Output<H>> = Vec::new();
		leaves
			// NOTE: We have the `ParallelDigest` crate for that, which we do NOT use here.
			// This is because we think that the `ParallelDigest` trait should perhaps be
			// redesigned. After a redesign, we should switch to using `ParallelDigest` here.
			.par_chunks_exact(1 << log_batch_size)
			.map(|leave_batch| hash_serialize::<T, H>(leave_batch).unwrap())
			.collect_into_vec(&mut leaf_batch_digests);

		// construct inner nodes
		let mut nodes = vec![leaf_batch_digests];
		for log_len in (commit_layer..log_leaf_batches).rev() {
			let mut layer = Vec::with_capacity(1 << log_len);
			// compress the previous layer
			nodes
				.last()
				.unwrap()
				.par_chunks_exact(2)
				.map(|pair| compression.compress([pair[0].clone(), pair[1].clone()]))
				.collect_into_vec(&mut layer);
			nodes.push(layer);
		}
		assert_eq!(nodes.len(), log_leaf_batches - commit_layer + 1);

		// commit layer with index `commit_layer` to `transcript`
		transcript.write_slice(nodes.last().unwrap());

		// return instance which can be used later for proving openings
		Self {
			digest: PhantomData,
			compression: PhantomData,
			leaves,
			nodes,
			log_batch_size,
			log_leaf_batches,
			commit_layer,
		}
	}

	/// Proves opening of a leaf batch.
	///
	/// The counterpart on the verifier side is [`MerkleTreeVerifier::verify_opening`].
	///
	/// Arguments:
	/// - `leaf_batch_index`: The index of the leaf batch whose opening proof should be constructed.
	/// - `transcript`: The [`TranscriptWriter`] which is used for writing the opening proof.
	pub fn prove_opening(
		&self,
		leaf_batch_index: usize,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) {
		assert!(leaf_batch_index < (1 << self.log_leaf_batches));

		// write leaf batch
		let batch_range_start = leaf_batch_index << self.log_batch_size;
		let batch_range_end = (leaf_batch_index + 1) << self.log_batch_size;
		transcript.write_slice(&self.leaves[batch_range_start..batch_range_end]);

		// write merkle path up to `self.commit_layer`
		for i in 0..(self.log_leaf_batches - self.commit_layer) {
			let index_in_layer = leaf_batch_index >> i;
			let index_sibling = index_in_layer ^ 1;
			transcript.write(&self.nodes[i][index_sibling]);
		}
	}

	/// Provides access to the leaf batches in form of a [`IndexedParallelIterator`].
	pub fn par_leaf_batches(&self) -> impl IndexedParallelIterator<Item = &[T]> {
		self.leaves.par_chunks_exact(1 << self.log_batch_size)
	}

	pub fn log_leaf_batches(&self) -> usize {
		self.log_leaf_batches
	}

	/// Number of leaves. (Not leaf batches!)
	pub fn log_leaves(&self) -> usize {
		self.log_leaf_batches + self.log_batch_size
	}

	/// Base-2 logarithm of leaf batch size.
	pub fn log_batch_size(&self) -> usize {
		self.log_batch_size
	}
}

/// Provides the ability to batch [`MerkleTreeProver`]s together.
pub struct BatchedMerkleTreeProver<F, H: OutputSizeUser, C> {
	compression: C,
	provers: Vec<MerkleTreeProver<F, H, C>>,
	// NOTE: Alternatively one could not compute this at all and instead save `batched_challenges`
	// and compute `batched_leaves` ad-hoc, which would save a lot of memory.
	batched_leaves: Option<Vec<F>>,
	log_leaves: usize,
	log_batch_size: usize,
	commit_layer: usize,
}

impl<F, H, C> BatchedMerkleTreeProver<F, H, C>
where
	F: BinaryField,
	H: Digest + BlockSizeUser,
	C: PseudoCompressionFunction<Output<H>, 2> + Sync,
{
	/// Batches `provers` together using `batch_challenges`.
	///
	/// ## Preconditions
	///
	/// - `batch_challenges.len() + 1 == provers.len()`
	pub fn new(
		compression: C,
		log_leaves: usize,
		log_batch_size: usize,
		commit_layer: usize,
	) -> Self {
		assert!(log_batch_size <= log_leaves);

		Self {
			compression,
			provers: Vec::new(),
			batched_leaves: None,
			log_leaves,
			log_batch_size,
			commit_layer,
		}
	}

	pub fn write_commitment(
		&mut self,
		leaves: Vec<F>,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) {
		assert!(self.batched_leaves.is_none());
		let log_leaves = log2_strict_usize(leaves.len());
		assert!(log_leaves <= self.log_leaves);

		let log_leaves_diff = self.log_leaves - log_leaves;
		let log_batch_size = self.log_batch_size.saturating_sub(log_leaves_diff);

		let prover = MerkleTreeProver::write_commitment(
			self.compression.clone(),
			leaves,
			log_batch_size,
			self.commit_layer,
			transcript,
		);
		self.provers.push(prover);
	}

	pub fn add_batch_challenges(&mut self, batch_challenges: Vec<F>) {
		assert!(self.batched_leaves.is_none());
		assert_eq!(batch_challenges.len() + 1, self.provers.len());

		// batch leaves
		// FIXME NOTE We could just drop this computation (and not have `batched_leaves` at all,
		// instead one would save `batch_challenges`). That's because this is only needed in
		// `par_leaf_batches()`, and there we could compute it ad-hoc.
		let mut batched_leaves: Vec<F> = vec![F::ZERO; 1 << self.log_leaves];
		{
			let prover = &self.provers[0];

			assert!(prover.log_batch_size() <= self.log_batch_size);
			let log_batch_size_diff = self.log_batch_size - prover.log_batch_size();
			assert!(prover.log_leaf_batches() <= self.log_leaf_batches());
			let log_leaf_batch_diff = self.log_leaf_batches() - prover.log_leaf_batches();
			for i in 0..(1 << (self.log_leaves - log_batch_size_diff)) {
				batched_leaves[i << log_batch_size_diff] = prover.leaves[i >> log_leaf_batch_diff];
			}
		}
		for (prover, &batch_challenge) in self.provers[1..].iter().zip(batch_challenges.iter()) {
			assert!(prover.log_batch_size() <= self.log_batch_size);
			let log_batch_size_diff = self.log_batch_size - prover.log_batch_size();
			assert!(prover.log_leaf_batches() <= self.log_leaf_batches());
			let log_leaf_batch_diff = self.log_leaf_batches() - prover.log_leaf_batches();

			for i in 0..(1 << (self.log_leaves - log_batch_size_diff)) {
				batched_leaves[i << log_batch_size_diff] +=
					batch_challenge * prover.leaves[i >> log_leaf_batch_diff];
			}
		}

		self.batched_leaves = Some(batched_leaves);
	}

	/// Proves opening of a batched leaf batch.
	///
	/// This simply calls [`MerkleTreeProver::prove_opening`] on all the `provers`.
	pub fn prove_opening(
		&self,
		leaf_batch_index: usize,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) {
		assert!(self.batched_leaves.is_some());

		for prover in &self.provers {
			assert!(prover.log_leaf_batches() <= self.log_leaf_batches());
			let log_leaf_batches_diff = self.log_leaf_batches() - prover.log_leaf_batches();

			prover.prove_opening(leaf_batch_index >> log_leaf_batches_diff, transcript);
		}
	}

	pub fn par_leaf_batches(&self) -> impl IndexedParallelIterator<Item = &[F]> {
		// FIXME NOTE We could just construct this iterator ad-hoc (batch the leaf batches together
		// in the moment when we are iterating), and then we wouln't need `self.batched_leaves`,
		// which would save a lot of memory.
		let batched_leaves = self.batched_leaves.as_ref().unwrap();
		batched_leaves.par_chunks_exact(1 << self.log_batch_size())
	}

	pub fn log_leaf_batches(&self) -> usize {
		self.log_leaves - self.log_batch_size
	}

	pub fn log_leaves(&self) -> usize {
		self.log_leaves
	}

	pub fn log_batch_size(&self) -> usize {
		self.log_batch_size
	}
}

#[cfg(test)]
mod tests {
	use std::iter::repeat_with;

	use binius_field::{BinaryField128bGhash, Random};
	use binius_transcript::ProverTranscript;
	use binius_utils::DeserializeBytes;
	use binius_verifier::{
		config::StdChallenger,
		hash::{StdCompression, StdDigest},
		merkle_tree::MerkleTreeVerifier,
	};
	use rand::prelude::*;

	use super::*;

	fn test_commit_prove_verify<
		T: SerializeBytes + DeserializeBytes + Sync + std::fmt::Debug + std::cmp::PartialEq + Clone,
	>(
		leaves: Vec<T>,
		log_batch_size: usize,
		commit_layer: usize,
		query_indices: &[usize],
	) {
		// store leaves for later comparison
		let leaves_copy = leaves.clone();

		let log_leaves = log2_strict_usize(leaves.len());

		// fix compression function (for inner nodes) and hash function (for leaves)
		let compression = StdCompression::default();
		type H = StdDigest;

		// create prover transcript
		let challenger = StdChallenger::default();
		let mut prover_transcript = ProverTranscript::new(challenger);

		// commit
		let prover = MerkleTreeProver::<_, H, _>::write_commitment(
			compression.clone(),
			leaves,
			log_batch_size,
			commit_layer,
			&mut prover_transcript.message(),
		);

		// prove openings
		for &index in query_indices {
			prover.prove_opening(index, &mut prover_transcript.decommitment());
		}

		// turn into verifier transcript
		let mut verifier_transcript = prover_transcript.into_verifier();

		// read commitment
		let verifier = MerkleTreeVerifier::<T, H, _>::read_commitment(
			compression,
			log_leaves,
			log_batch_size,
			commit_layer,
			&mut verifier_transcript.message(),
		);

		// verify openings
		for &index in query_indices {
			let leaf_batch = verifier
				.verify_opening(index, &mut verifier_transcript.decommitment())
				.unwrap();
			// check that the returned leaf batch agrees with the original leaves
			let leaves_from = index << log_batch_size;
			let leaves_to = (index + 1) << log_batch_size;
			assert_eq!(leaf_batch, &leaves_copy[leaves_from..leaves_to]);
		}
	}

	#[test]
	fn test_commit_prove_verify_ghash() {
		type F = BinaryField128bGhash;

		let mut rng = StdRng::seed_from_u64(0);
		let leaves: Vec<F> = repeat_with(|| F::random(&mut rng)).take(32).collect();

		for commit_layer in [0, 1, 2, 1000] {
			// log_batch_size = 0
			test_commit_prove_verify(leaves.clone(), 0, commit_layer, &[0, 21, 31]);
			// log_batch_size = 2
			test_commit_prove_verify(leaves.clone(), 2, commit_layer, &[0, 4, 7]);
		}
	}
}
