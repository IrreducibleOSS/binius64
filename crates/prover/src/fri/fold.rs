// Copyright 2024-2025 Irreducible Inc.

use binius_field::{BinaryField, ExtensionField, PackedField, packed::len_packed_slice};
use binius_math::{multilinear::eq::eq_ind_partial_eval, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::{
	SerializeBytes, bail, checked_arithmetics::log2_strict_usize, rayon::prelude::*,
};
use binius_verifier::{
	fri::{FRIParams, fold::fold_interleaved_chunk},
	merkle_tree::MerkleTreeScheme,
};
use bytemuck::zeroed_vec;
use tracing::instrument;

use super::{error::Error, query::FRIQueryProver};
use crate::merkle_tree::MerkleTreeProver;

/// The type of the termination round codeword in the FRI protocol.
pub type TerminateCodeword<F> = Vec<F>;

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
	F: BinaryField + ExtensionField<FA>,
	FA: BinaryField,
	P: PackedField<Scalar = F>,
	NTT: AdditiveNTT<Field = FA> + Sync,
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
	pub fn n_rounds(&self) -> usize {
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

		let _fri_round_scope = tracing::debug_span!(
			"FRI Round",
			log_len = log2_strict_usize(self.current_codeword_len()),
			arity = self.unprocessed_challenges.len()
		)
		.entered();

		// Fold the last codeword with the accumulated folding challenges.
		let fri_fold_span = tracing::debug_span!("FRI Fold").entered();
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
		let merkle_tree_span = tracing::debug_span!("Merkle Tree").entered();
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

/// FRI-fold the interleaved codeword using the given challenges.
///
/// ## Arguments
///
/// * `ntt` - the NTT instance, used to look up the twiddle values.
/// * `codeword` - an interleaved codeword.
/// * `challenges` - the folding challenges. The length must be at least `log_batch_size`.
/// * `log_len` - the binary logarithm of the code length.
/// * `log_batch_size` - the binary logarithm of the interleaved code batch size.
///
/// See [DP24], Def. 3.6 and Lemma 3.9 for more details.
///
/// [DP24]: <https://eprint.iacr.org/2024/504>
#[instrument(skip_all, level = "debug")]
fn fold_interleaved_allocated<F, FS, NTT, P>(
	ntt: &NTT,
	codeword: &[P],
	challenges: &[F],
	log_len: usize,
	log_batch_size: usize,
	out: &mut [F],
) where
	F: BinaryField + ExtensionField<FS>,
	FS: BinaryField,
	NTT: AdditiveNTT<Field = FS> + Sync,
	P: PackedField<Scalar = F>,
{
	assert_eq!(codeword.len(), 1 << (log_len + log_batch_size).saturating_sub(P::LOG_WIDTH));
	assert!(challenges.len() >= log_batch_size);
	assert_eq!(out.len(), 1 << (log_len - (challenges.len() - log_batch_size)));

	let (interleave_challenges, fold_challenges) = challenges.split_at(log_batch_size);
	let tensor = eq_ind_partial_eval(interleave_challenges);

	// For each chunk of size `2^chunk_size` in the codeword, fold it with the folding challenges
	let fold_chunk_size = 1 << fold_challenges.len();
	let chunk_size = 1 << challenges.len().saturating_sub(P::LOG_WIDTH);
	codeword
		.par_chunks(chunk_size)
		.enumerate()
		.zip(out)
		.for_each_init(
			|| vec![F::default(); fold_chunk_size],
			|scratch_buffer, ((i, chunk), out)| {
				*out = fold_interleaved_chunk(
					ntt,
					log_len,
					log_batch_size,
					i,
					chunk,
					tensor.as_ref(),
					fold_challenges,
					scratch_buffer,
				)
			},
		)
}

fn fold_interleaved<F, FS, NTT, P>(
	ntt: &NTT,
	codeword: &[P],
	challenges: &[F],
	log_len: usize,
	log_batch_size: usize,
) -> Vec<F>
where
	F: BinaryField + ExtensionField<FS>,
	FS: BinaryField,
	NTT: AdditiveNTT<Field = FS> + Sync,
	P: PackedField<Scalar = F>,
{
	let mut result =
		zeroed_vec(1 << log_len.saturating_sub(challenges.len().saturating_sub(log_batch_size)));
	fold_interleaved_allocated(ntt, codeword, challenges, log_len, log_batch_size, &mut result);
	result
}

#[cfg(test)]
mod tests {
	use binius_math::{
		BinarySubspace, FieldBuffer,
		fold::fold_cols,
		ntt::{NeighborsLastSingleThread, domain_context::GenericOnTheFly},
		test_utils::random_scalars,
	};
	use binius_verifier::config::B128;
	use proptest::prelude::*;
	use rand::prelude::*;

	use super::*;

	proptest! {
		#[test]
		fn test_fri_compatible_ntt_domains(log_dim in 0..8usize, arity in 0..4usize) {
			test_help_fri_compatible_ntt_domains(log_dim, arity);
		}
	}

	fn test_help_fri_compatible_ntt_domains(log_dim: usize, arity: usize) {
		let subspace = BinarySubspace::with_dim(32).unwrap();
		let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
		let ntt = NeighborsLastSingleThread { domain_context };

		let mut rng = StdRng::seed_from_u64(0);
		let msg = random_scalars(&mut rng, 1 << (log_dim + arity));
		let challenges = random_scalars(&mut rng, arity);

		let query = eq_ind_partial_eval::<B128>(&challenges);

		// Fold the message using regular folding.
		let msg_buffer = FieldBuffer::new(log_dim + arity, msg.as_slice()).unwrap();
		let mut folded_msg = fold_cols(&msg_buffer, &query).unwrap();
		assert_eq!(folded_msg.log_len(), log_dim);

		// Encode the message over the large domain.
		let mut codeword = msg;
		ntt.forward_transform(&mut codeword, 0, 0);

		// Fold the encoded message using FRI folding.
		let folded_codeword = fold_interleaved(&ntt, &codeword, &challenges, log_dim + arity, 0);

		// Encode the folded message.
		ntt.forward_transform(folded_msg.as_mut(), 0, 0);

		// Check that folding and encoding commute.
		assert_eq!(folded_codeword, folded_msg.as_ref());
	}
}
