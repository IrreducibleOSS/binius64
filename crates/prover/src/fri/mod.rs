// Copyright 2024-2025 Irreducible Inc.

mod error;
mod fold;
mod logging;

use binius_field::{
	BinaryField, ExtensionField, PackedExtension, PackedField, TowerField,
	packed::{iter_packed_slice_with_offset, len_packed_slice},
};
use binius_math::{ReedSolomonCode, ntt::AdditiveNTT};
use binius_maybe_rayon::prelude::*;
use binius_transcript::{
	ProverTranscript, TranscriptWriter,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::{SerializeBytes, bail, checked_arithmetics::log2_strict_usize};
use binius_verifier::{
	fri::{FRIParams, vcs_optimal_layers_depths_iter},
	merkle_tree::MerkleTreeScheme,
};
use bytemuck::zeroed_vec;
use bytes::BufMut;
pub use error::Error;
use fold::fold_interleaved;
use itertools::izip;
use logging::{
	FRIFoldData, MerkleTreeDimensionData, RSEncodeDimensionData, SortAndMergeDimensionData,
};
use tracing::instrument;

use crate::merkle_tree::MerkleTreeProver;

#[derive(Debug)]
pub struct CommitOutput<P, VCSCommitment, VCSCommitted> {
	pub commitment: VCSCommitment,
	pub committed: VCSCommitted,
	pub codeword: Vec<P>,
}

/// The type of the termination round codeword in the FRI protocol.
pub type TerminateCodeword<F> = Vec<F>;

/// Creates a parallel iterator over scalars of subfield elementsAssumes chunk_size to be a power of
/// two
pub fn to_par_scalar_big_chunks<P>(
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

pub fn to_par_scalar_small_chunks<P>(
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

pub enum FoldRoundOutput<VCSCommitment> {
	NoCommitment,
	Commitment(VCSCommitment),
}

/// A stateful prover for the FRI fold phase.
pub struct FRIFolder<'a, F, FA, P, NTT, MerkleProver, VCS>
where
	FA: BinaryField,
	F: BinaryField,
	P: PackedField<Scalar = F>,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	params: &'a FRIParams<F, FA>,
	ntt: &'a NTT,
	merkle_prover: &'a MerkleProver,
	codeword: &'a [P],
	codeword_committed: &'a MerkleProver::Committed,
	round_committed: Vec<(Vec<F>, MerkleProver::Committed)>,
	curr_round: usize,
	next_commit_round: Option<usize>,
	unprocessed_challenges: Vec<F>,
}

impl<'a, F, FA, P, NTT, MerkleProver, VCS> FRIFolder<'a, F, FA, P, NTT, MerkleProver, VCS>
where
	F: TowerField + ExtensionField<FA>,
	FA: BinaryField,
	P: PackedField<Scalar = F>,
	NTT: AdditiveNTT<FA> + Sync,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
{
	/// Constructs a new folder.
	pub fn new(
		params: &'a FRIParams<F, FA>,
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		committed_codeword: &'a [P],
		committed: &'a MerkleProver::Committed,
	) -> Result<Self, Error> {
		if len_packed_slice(committed_codeword) < 1 << params.log_len() {
			bail!(Error::InvalidArgs(
				"Reed–Solomon code length must match interleaved codeword length".to_string(),
			));
		}

		let next_commit_round = params.fold_arities().first().copied();
		Ok(Self {
			params,
			ntt,
			merkle_prover,
			codeword: committed_codeword,
			codeword_committed: committed,
			round_committed: Vec::with_capacity(params.n_oracles()),
			curr_round: 0,
			next_commit_round,
			unprocessed_challenges: Vec::with_capacity(params.rs_code().log_dim()),
		})
	}

	/// Number of fold rounds, including the final fold.
	pub const fn n_rounds(&self) -> usize {
		self.params.n_fold_rounds()
	}

	/// Number of times `execute_fold_round` has been called.
	pub const fn curr_round(&self) -> usize {
		self.curr_round
	}

	/// The length of the current codeword.
	pub fn current_codeword_len(&self) -> usize {
		match self.round_committed.last() {
			Some((codeword, _)) => codeword.len(),
			None => len_packed_slice(self.codeword),
		}
	}

	fn is_commitment_round(&self) -> bool {
		self.next_commit_round
			.is_some_and(|round| round == self.curr_round)
	}

	/// Executes the next fold round and returns the folded codeword commitment.
	///
	/// As a memory efficient optimization, this method may not actually do the folding, but instead
	/// accumulate the folding challenge for processing at a later time. This saves us from storing
	/// intermediate folded codewords.
	pub fn execute_fold_round(
		&mut self,
		challenge: F,
	) -> Result<FoldRoundOutput<VCS::Digest>, Error> {
		self.unprocessed_challenges.push(challenge);
		self.curr_round += 1;

		if !self.is_commitment_round() {
			return Ok(FoldRoundOutput::NoCommitment);
		}

		let dimensions_data = match self.round_committed.last() {
			Some((codeword, _)) => FRIFoldData::new::<F, FA>(
				log2_strict_usize(codeword.len()),
				0,
				self.unprocessed_challenges.len(),
			),
			None => FRIFoldData::new::<F, FA>(
				self.params.rs_code().log_len(),
				self.params.log_batch_size(),
				self.unprocessed_challenges.len(),
			),
		};

		let fri_fold_span = tracing::debug_span!(
			"[task] FRI Fold",
			phase = "piop_compiler",
			perfetto_category = "task.main",
			?dimensions_data
		)
		.entered();
		// Fold the last codeword with the accumulated folding challenges.
		let folded_codeword = match self.round_committed.last() {
			Some((prev_codeword, _)) => {
				// Fold a full codeword committed in the previous FRI round into a codeword with
				// reduced dimension and rate.
				fold_interleaved(
					self.ntt,
					prev_codeword,
					&self.unprocessed_challenges,
					log2_strict_usize(prev_codeword.len()),
					0,
				)
			}
			None => {
				// Fold the interleaved codeword that was originally committed into a single
				// codeword with the same or reduced block length, depending on the sequence of
				// fold rounds.
				fold_interleaved(
					self.ntt,
					self.codeword,
					&self.unprocessed_challenges,
					self.params.rs_code().log_len(),
					self.params.log_batch_size(),
				)
			}
		};
		drop(fri_fold_span);
		self.unprocessed_challenges.clear();

		// take the first arity as coset_log_len, or use inv_rate if arities are empty
		let coset_size = self
			.params
			.fold_arities()
			.get(self.round_committed.len() + 1)
			.map(|log| 1 << log)
			.unwrap_or_else(|| 1 << self.params.n_final_challenges());
		let dimension_data =
			MerkleTreeDimensionData::new::<F>(dimensions_data.log_len(), coset_size);
		let merkle_tree_span = tracing::debug_span!(
			"[task] Merkle Tree",
			phase = "piop_compiler",
			perfetto_category = "task.main",
			dimensions_data = ?dimension_data
		)
		.entered();
		let (commitment, committed) = self.merkle_prover.commit(&folded_codeword, coset_size)?;
		drop(merkle_tree_span);

		self.round_committed.push((folded_codeword, committed));

		self.next_commit_round = self.next_commit_round.take().and_then(|next_commit_round| {
			let arity = self.params.fold_arities().get(self.round_committed.len())?;
			Some(next_commit_round + arity)
		});
		Ok(FoldRoundOutput::Commitment(commitment.root))
	}

	/// Finalizes the FRI folding process.
	///
	/// This step will process any unprocessed folding challenges to produce the
	/// final folded codeword. Then it will decode this final folded codeword
	/// to get the final message. The result is the final message and a query prover instance.
	///
	/// This returns the final message and a query prover instance.
	#[instrument(skip_all, name = "fri::FRIFolder::finalize", level = "debug")]
	#[allow(clippy::type_complexity)]
	pub fn finalize(
		mut self,
	) -> Result<(TerminateCodeword<F>, FRIQueryProver<'a, F, FA, P, MerkleProver, VCS>), Error> {
		if self.curr_round != self.n_rounds() {
			bail!(Error::EarlyProverFinish);
		}

		let terminate_codeword = self
			.round_committed
			.last()
			.map(|(codeword, _)| codeword.clone())
			.unwrap_or_else(|| PackedField::iter_slice(self.codeword).collect());

		self.unprocessed_challenges.clear();

		let Self {
			params,
			codeword,
			codeword_committed,
			round_committed,
			merkle_prover,
			..
		} = self;

		let query_prover = FRIQueryProver {
			params,
			codeword,
			codeword_committed,
			round_committed,
			merkle_prover,
		};
		Ok((terminate_codeword, query_prover))
	}

	pub fn finish_proof<Challenger_>(
		self,
		transcript: &mut ProverTranscript<Challenger_>,
	) -> Result<(), Error>
	where
		Challenger_: Challenger,
	{
		let (terminate_codeword, query_prover) = self.finalize()?;
		let mut advice = transcript.decommitment();
		advice.write_scalar_slice(&terminate_codeword);

		let layers = query_prover.vcs_optimal_layers()?;
		for layer in layers {
			advice.write_slice(&layer);
		}

		let params = query_prover.params;

		for _ in 0..params.n_test_queries() {
			let index = transcript.sample_bits(params.index_bits()) as usize;
			query_prover.prove_query(index, transcript.decommitment())?;
		}

		Ok(())
	}
}

/// A prover for the FRI query phase.
pub struct FRIQueryProver<'a, F, FA, P, MerkleProver, VCS>
where
	F: BinaryField,
	FA: BinaryField,
	P: PackedField<Scalar = F>,
	MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
	VCS: MerkleTreeScheme<F>,
{
	params: &'a FRIParams<F, FA>,
	codeword: &'a [P],
	codeword_committed: &'a MerkleProver::Committed,
	round_committed: Vec<(Vec<F>, MerkleProver::Committed)>,
	merkle_prover: &'a MerkleProver,
}

impl<F, FA, P, MerkleProver, VCS> FRIQueryProver<'_, F, FA, P, MerkleProver, VCS>
where
	F: TowerField + ExtensionField<FA>,
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
	F: TowerField,
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
