use binius_maybe_rayon::prelude::IndexedParallelIterator;
use binius_transcript::{BufMut, TranscriptWriter};
use binius_verifier::merkle_tree::{Commitment, Error, MerkleTreeScheme};

pub mod binary_merkle_tree;
pub mod prover;
#[cfg(test)]
mod tests;

/// A Merkle tree prover for a particular scheme.
///
/// This is separate from [`MerkleTreeScheme`] so that it may be implemented using a
/// hardware-accelerated backend.
pub trait MerkleTreeProver<T>: Sync {
	type Scheme: MerkleTreeScheme<T>;
	/// Data generated during commitment required to generate opening proofs.
	type Committed;

	/// Returns the Merkle tree scheme used by the prover.
	fn scheme(&self) -> &Self::Scheme;

	/// Commit a vector of values.
	#[allow(clippy::type_complexity)]
	fn commit(
		&self,
		data: &[T],
		batch_size: usize,
	) -> Result<(Commitment<<Self::Scheme as MerkleTreeScheme<T>>::Digest>, Self::Committed), Error>;

	/// Commit interleaved elements from iterator by val
	#[allow(clippy::type_complexity)]
	fn commit_iterated<ParIter>(
		&self,
		iterated_chunks: ParIter,
		log_len: usize,
	) -> Result<(Commitment<<Self::Scheme as MerkleTreeScheme<T>>::Digest>, Self::Committed), Error>
	where
		ParIter: IndexedParallelIterator<Item: IntoIterator<Item = T>>;

	/// Returns the internal digest layer at the given depth.
	fn layer<'a>(
		&self,
		committed: &'a Self::Committed,
		layer_depth: usize,
	) -> Result<&'a [<Self::Scheme as MerkleTreeScheme<T>>::Digest], Error>;

	/// Generate an opening proof for an entry in a committed vector at the given index.
	///
	/// ## Arguments
	///
	/// * `committed` - helper data generated during commitment
	/// * `layer_depth` - depth of the layer to prove inclusion in
	/// * `index` - the entry index
	fn prove_opening<B: BufMut>(
		&self,
		committed: &Self::Committed,
		layer_depth: usize,
		index: usize,
		proof: &mut TranscriptWriter<B>,
	) -> Result<(), Error>;
}
