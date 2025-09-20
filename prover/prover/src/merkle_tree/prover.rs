// Copyright 2024-2025 Irreducible Inc.

use binius_field::Field;
use binius_transcript::{BufMut, TranscriptWriter};
use binius_utils::rayon::iter::IndexedParallelIterator;
use binius_verifier::merkle_tree::{BinaryMerkleTreeScheme, Commitment, Error, MerkleTreeScheme};
use digest::{FixedOutputReset, Output, core_api::BlockSizeUser};
use getset::Getters;
use rand::{SeedableRng, rngs::StdRng};

use super::MerkleTreeProver;
use crate::{
	hash::{ParallelDigest, parallel_compression::ParallelPseudoCompression},
	merkle_tree::binary_merkle_tree::{self, BinaryMerkleTree},
};

#[derive(Debug, Getters)]
pub struct BinaryMerkleTreeProver<T, H: ParallelDigest, C>
where
	C: ParallelPseudoCompression<Output<H::Digest>, 2>,
{
	#[getset(get = "pub")]
	scheme: BinaryMerkleTreeScheme<T, H::Digest, C::Compression>,
	parallel_compression: C,
	salt_len: usize,
}

impl<T, C, H: ParallelDigest> BinaryMerkleTreeProver<T, H, C>
where
	C: ParallelPseudoCompression<Output<H::Digest>, 2>,
	C::Compression: Clone,
{
	pub fn new(parallel_compression: C) -> Self {
		Self::hiding(parallel_compression, 0)
	}

	pub fn hiding(parallel_compression: C, salt_len: usize) -> Self {
		Self {
			scheme: BinaryMerkleTreeScheme::hiding(
				parallel_compression.compression().clone(),
				salt_len,
			),
			parallel_compression,
			salt_len,
		}
	}
}

impl<F, H, C> MerkleTreeProver<F> for BinaryMerkleTreeProver<F, H, C>
where
	F: Field,
	H: ParallelDigest<Digest: BlockSizeUser + FixedOutputReset>,
	C: ParallelPseudoCompression<Output<H::Digest>, 2>,
{
	type Scheme = BinaryMerkleTreeScheme<F, H::Digest, C::Compression>;
	type Committed = BinaryMerkleTree<Output<H::Digest>, F>;

	fn scheme(&self) -> &Self::Scheme {
		&self.scheme
	}

	fn commit(
		&self,
		data: &[F],
		batch_size: usize,
	) -> Result<(Commitment<Output<H::Digest>>, Self::Committed), Error> {
		let tree = binary_merkle_tree::build::<_, H, _, _>(
			&self.parallel_compression,
			data,
			batch_size,
			self.salt_len,
			StdRng::seed_from_u64(0),
		)?;

		let commitment = Commitment {
			root: tree.root(),
			depth: tree.log_len,
		};

		Ok((commitment, tree))
	}

	fn layer<'a>(
		&self,
		committed: &'a Self::Committed,
		depth: usize,
	) -> Result<&'a [Output<H::Digest>], Error> {
		committed.layer(depth)
	}

	fn prove_opening<B: BufMut>(
		&self,
		committed: &Self::Committed,
		layer_depth: usize,
		index: usize,
		proof: &mut TranscriptWriter<B>,
	) -> Result<(), Error> {
		let salt = committed.get_salt(index >> layer_depth);
		proof.write_slice(salt);

		let branch = committed.branch(index, layer_depth)?;
		proof.write_slice(&branch);
		Ok(())
	}

	#[allow(clippy::type_complexity)]
	fn commit_iterated<ParIter>(
		&self,
		leaves: ParIter,
	) -> Result<(Commitment<<Self::Scheme as MerkleTreeScheme<F>>::Digest>, Self::Committed), Error>
	where
		ParIter: IndexedParallelIterator<Item: IntoIterator<Item = F, IntoIter: Send>>,
	{
		let tree = binary_merkle_tree::build_from_iterator::<F, H, _, _, _>(
			&self.parallel_compression,
			leaves,
			self.salt_len,
			StdRng::seed_from_u64(0),
		)?;

		let commitment = Commitment {
			root: tree.root(),
			depth: tree.log_len,
		};

		Ok((commitment, tree))
	}
}
