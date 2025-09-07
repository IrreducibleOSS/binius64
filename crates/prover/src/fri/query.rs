// Copyright 2025 Irreducible Inc.
use binius_field::{
	BinaryField, ExtensionField, PackedField, packed::iter_packed_slice_with_offset,
};
use binius_transcript::TranscriptWriter;
use binius_verifier::{
	fri::{FRIParams, vcs_optimal_layers_depths_iter},
	merkle_tree::MerkleTreeScheme,
};
use bytes::BufMut;
use itertools::izip;
use tracing::instrument;

use crate::{fri::Error, merkle_tree::MerkleTreeProver};

/// A prover for the FRI query phase.
#[derive(Debug)]
pub struct FRIQueryProver<'a, F, FA, P, MerkleProver, VCS>
where
	F: BinaryField,
	FA: BinaryField,
	P: PackedField<Scalar = F>,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	pub(super) params: &'a FRIParams<F, FA>,
	pub(super) codeword: &'a [P],
	pub(super) codeword_committed: &'a MerkleProver::Committed,
	pub(super) round_committed: Vec<(Vec<F>, MerkleProver::Committed)>,
	pub(super) merkle_prover: &'a MerkleProver,
}

impl<F, FA, P, MerkleProver, VCS> FRIQueryProver<'_, F, FA, P, MerkleProver, VCS>
where
	F: BinaryField + ExtensionField<FA>,
	FA: BinaryField,
	P: PackedField<Scalar = F>,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	/// Number of oracles sent during the fold rounds.
	pub fn n_oracles(&self) -> usize {
		self.params.n_oracles()
	}

	/// Proves a FRI challenge query.
	///
	/// ## Arguments
	///
	/// * `index` - an index into the original codeword domain
	#[instrument(skip_all, name = "fri::FRIQueryProver::prove_query", level = "debug")]
	pub fn prove_query<B>(
		&self,
		mut index: usize,
		mut advice: TranscriptWriter<B>,
	) -> Result<(), Error>
	where
		B: BufMut,
	{
		let mut arities_and_optimal_layers_depths = self
			.params
			.fold_arities()
			.iter()
			.copied()
			.zip(vcs_optimal_layers_depths_iter(self.params, self.merkle_prover.scheme()));

		let Some((first_fold_arity, first_optimal_layer_depth)) =
			arities_and_optimal_layers_depths.next()
		else {
			// If there are no query proofs, that means that no oracles were sent during the FRI
			// fold rounds. In that case, the original interleaved codeword is decommitted and
			// the only checks that need to be performed are in `verify_last_oracle`.
			return Ok(());
		};

		prove_coset_opening(
			self.merkle_prover,
			self.codeword,
			self.codeword_committed,
			index,
			first_fold_arity,
			first_optimal_layer_depth,
			&mut advice,
		)?;

		for ((codeword, committed), (arity, optimal_layer_depth)) in
			izip!(self.round_committed.iter(), arities_and_optimal_layers_depths)
		{
			index >>= arity;
			prove_coset_opening(
				self.merkle_prover,
				codeword,
				committed,
				index,
				arity,
				optimal_layer_depth,
				&mut advice,
			)?;
		}

		Ok(())
	}

	pub fn vcs_optimal_layers(&self) -> Result<Vec<Vec<VCS::Digest>>, Error> {
		let committed_iter = std::iter::once(self.codeword_committed)
			.chain(self.round_committed.iter().map(|(_, committed)| committed));

		committed_iter
			.zip(vcs_optimal_layers_depths_iter(self.params, self.merkle_prover.scheme()))
			.map(|(committed, optimal_layer_depth)| {
				let layer = self.merkle_prover.layer(committed, optimal_layer_depth)?;
				Ok(layer.to_vec())
			})
			.collect::<Result<Vec<_>, _>>()
	}
}

fn prove_coset_opening<F, P, MTProver, B>(
	merkle_prover: &MTProver,
	codeword: &[P],
	committed: &MTProver::Committed,
	coset_index: usize,
	log_coset_size: usize,
	optimal_layer_depth: usize,
	advice: &mut TranscriptWriter<B>,
) -> Result<(), Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	MTProver: MerkleTreeProver<F>,
	B: BufMut,
{
	let values = iter_packed_slice_with_offset(codeword, coset_index << log_coset_size)
		.take(1 << log_coset_size);
	advice.write_scalar_iter(values);

	merkle_prover.prove_opening(committed, optimal_layer_depth, coset_index, advice)?;

	Ok(())
}
