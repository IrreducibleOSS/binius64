// Copyright 2024-2025 Irreducible Inc.

use std::iter;

use binius_field::{BinaryField, ExtensionField};
use binius_math::{
	FieldBuffer,
	multilinear::eq::eq_ind_partial_eval,
	ntt::{NeighborsLastSingleThread, domain_context::GenericOnTheFly},
};
use binius_transcript::{
	TranscriptReader, VerifierTranscript,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::{DeserializeBytes, bail};
use bytes::Buf;
use itertools::izip;

use super::{
	common::{FRIParams, vcs_optimal_layers_depths_iter},
	error::{Error, VerificationError},
};
use crate::{
	fri::fold::{fold_chunk, fold_interleaved_chunk},
	merkle_tree::MerkleTreeScheme,
};

/// A verifier for the FRI query phase.
///
/// The verifier is instantiated after the folding rounds and is used to test consistency of the
/// round messages and the original purported codeword.
#[derive(Debug)]
pub struct FRIVerifier<'a, F, FA, VCS>
where
	F: BinaryField + ExtensionField<FA>,
	FA: BinaryField,
	VCS: MerkleTreeScheme<F>,
{
	vcs: &'a VCS,
	params: &'a FRIParams<F, FA>,
	/// Received commitment to the codeword.
	codeword_commitment: &'a VCS::Digest,
	/// Received commitments to the round messages.
	round_commitments: &'a [VCS::Digest],
	/// The challenges for each round.
	interleave_tensor: FieldBuffer<F>,
	/// The challenges for each round.
	fold_challenges: &'a [F],
}

impl<'a, F, FA, VCS> FRIVerifier<'a, F, FA, VCS>
where
	F: BinaryField + ExtensionField<FA>,
	FA: BinaryField,
	VCS: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		params: &'a FRIParams<F, FA>,
		vcs: &'a VCS,
		codeword_commitment: &'a VCS::Digest,
		round_commitments: &'a [VCS::Digest],
		challenges: &'a [F],
	) -> Result<Self, Error> {
		if round_commitments.len() != params.n_oracles() {
			bail!(Error::InvalidArgs(format!(
				"got {} round commitments, expected {}",
				round_commitments.len(),
				params.n_oracles(),
			)));
		}

		if challenges.len() != params.n_fold_rounds() {
			bail!(Error::InvalidArgs(format!(
				"got {} folding challenges, expected {}",
				challenges.len(),
				params.n_fold_rounds(),
			)));
		}

		let (interleave_challenges, fold_challenges) = challenges.split_at(params.log_batch_size());

		let interleave_tensor = eq_ind_partial_eval(interleave_challenges);
		Ok(Self {
			params,
			vcs,
			codeword_commitment,
			round_commitments,
			interleave_tensor,
			fold_challenges,
		})
	}

	/// Number of oracles sent during the fold rounds.
	pub fn n_oracles(&self) -> usize {
		self.params.n_oracles()
	}

	pub fn verify<Challenger_>(
		&self,
		transcript: &mut VerifierTranscript<Challenger_>,
	) -> Result<F, Error>
	where
		Challenger_: Challenger,
	{
		let subspace = self.params.rs_code().subspace();
		let domain_context = GenericOnTheFly::generate_from_subspace(subspace);
		let ntt = NeighborsLastSingleThread::new(domain_context);

		// Verify that the last oracle sent is a codeword.
		let terminate_codeword_len =
			1 << (self.params.n_final_challenges() + self.params.rs_code().log_inv_rate());
		let mut advice = transcript.decommitment();
		let terminate_codeword = advice
			.read_scalar_slice(terminate_codeword_len)
			.map_err(Error::TranscriptError)?;
		let final_value = self.verify_last_oracle(&ntt, &terminate_codeword)?;

		// Verify that the provided layers match the commitments.
		let layers = vcs_optimal_layers_depths_iter(self.params, self.vcs)
			.map(|layer_depth| advice.read_vec(1 << layer_depth))
			.collect::<Result<Vec<_>, _>>()?;
		for (commitment, layer_depth, layer) in izip!(
			iter::once(self.codeword_commitment).chain(self.round_commitments),
			vcs_optimal_layers_depths_iter(self.params, self.vcs),
			&layers
		) {
			self.vcs.verify_layer(commitment, layer_depth, layer)?;
		}

		// Verify the random openings against the decommitted layers.

		let mut scratch_buffer = self.create_scratch_buffer();
		for _ in 0..self.params.n_test_queries() {
			let index = transcript.sample_bits(self.params.index_bits()) as usize;
			self.verify_query_internal(
				index,
				&ntt,
				&terminate_codeword,
				&layers,
				&mut transcript.decommitment(),
				&mut scratch_buffer,
			)?
		}

		Ok(final_value)
	}

	/// Verifies that the last oracle sent is a codeword.
	///
	/// Returns the fully-folded message value.
	pub fn verify_last_oracle(
		&self,
		ntt: &NeighborsLastSingleThread<GenericOnTheFly<FA>>,
		terminate_codeword: &[F],
	) -> Result<F, Error> {
		let n_final_challenges = self.params.n_final_challenges();

		self.vcs.verify_vector(
			self.round_commitments
				.last()
				.unwrap_or(self.codeword_commitment),
			terminate_codeword,
			1 << n_final_challenges,
		)?;

		let repetition_codeword = if self.n_oracles() != 0 {
			let n_prior_challenges = self.fold_challenges.len() - n_final_challenges;
			let final_challenges = &self.fold_challenges[n_prior_challenges..];
			let mut scratch_buffer = vec![F::default(); 1 << n_final_challenges];

			terminate_codeword
				.chunks(1 << n_final_challenges)
				.enumerate()
				.map(|(i, coset_values)| {
					scratch_buffer.copy_from_slice(coset_values);
					fold_chunk(
						ntt,
						n_final_challenges + self.params.rs_code().log_inv_rate(),
						i,
						&mut scratch_buffer,
						final_challenges,
					)
				})
				.collect::<Vec<_>>()
		} else {
			// When the prover did not send any round oracles, fold the original interleaved
			// codeword.

			let fold_arity = self.params.rs_code().log_dim() + self.params.log_batch_size();
			let mut scratch_buffer = vec![F::default(); 1 << self.params.rs_code().log_dim()];
			terminate_codeword
				.chunks(1 << fold_arity)
				.enumerate()
				.map(|(i, chunk)| {
					fold_interleaved_chunk(
						ntt,
						self.params.rs_code().log_len(),
						self.params.log_batch_size(),
						i,
						chunk,
						self.interleave_tensor.as_ref(),
						self.fold_challenges,
						&mut scratch_buffer,
					)
				})
				.collect::<Vec<_>>()
		};

		let final_value = repetition_codeword[0];

		// Check that the fully-folded purported codeword is a repetition codeword.
		if repetition_codeword[1..]
			.iter()
			.any(|&entry| entry != final_value)
		{
			return Err(VerificationError::IncorrectDegree.into());
		}

		Ok(final_value)
	}

	/// Verifies a FRI challenge query.
	///
	/// A FRI challenge query tests for consistency between all consecutive oracles sent by the
	/// prover. The verifier has full access to the last oracle sent, and this is probabilistically
	/// verified to be a codeword by `Self::verify_last_oracle`.
	///
	/// ## Arguments
	///
	/// * `index` - an index into the original codeword domain
	/// * `proof` - a query proof
	pub fn verify_query<B: Buf>(
		&self,
		index: usize,
		ntt: &NeighborsLastSingleThread<GenericOnTheFly<FA>>,
		terminate_codeword: &[F],
		layers: &[Vec<VCS::Digest>],
		advice: &mut TranscriptReader<B>,
	) -> Result<(), Error> {
		self.verify_query_internal(
			index,
			ntt,
			terminate_codeword,
			layers,
			advice,
			&mut self.create_scratch_buffer(),
		)
	}

	fn verify_query_internal<B: Buf>(
		&self,
		mut index: usize,
		ntt: &NeighborsLastSingleThread<GenericOnTheFly<FA>>,
		terminate_codeword: &[F],
		layers: &[Vec<VCS::Digest>],
		advice: &mut TranscriptReader<B>,
		scratch_buffer: &mut [F],
	) -> Result<(), Error> {
		let mut arities_iter = self.params.fold_arities().iter().copied();

		let mut layer_digest_and_optimal_layer_depth =
			iter::zip(layers, vcs_optimal_layers_depths_iter(self.params, self.vcs));

		let Some(first_fold_arity) = arities_iter.next() else {
			// If there are no query proofs, that means that no oracles were sent during the FRI
			// fold rounds. In that case, the original interleaved codeword is decommitted and
			// the only checks that need to be performed are in `verify_last_oracle`.
			return Ok(());
		};

		let (first_layer, first_optimal_layer_depth) = layer_digest_and_optimal_layer_depth
			.next()
			.expect("The length should be the same as the amount of proofs.");

		// This is the round of the folding phase that the codeword to be folded is committed to.
		let mut fold_round = 0;
		let mut log_n_cosets = self.params.index_bits();

		// Check the first fold round before the main loop. It is special because in the first
		// round we need to fold as an interleaved chunk instead of a regular coset.
		let log_coset_size = first_fold_arity - self.params.log_batch_size();
		let values = verify_coset_opening(
			self.vcs,
			index,
			first_fold_arity,
			first_optimal_layer_depth,
			log_n_cosets,
			first_layer,
			advice,
		)?;
		let mut next_value = fold_interleaved_chunk(
			ntt,
			self.params.rs_code().log_len(),
			self.params.log_batch_size(),
			index,
			&values,
			self.interleave_tensor.as_ref(),
			&self.fold_challenges[fold_round..fold_round + log_coset_size],
			scratch_buffer,
		);
		fold_round += log_coset_size;

		for (i, (arity, (layer, optimal_layer_depth))) in
			izip!(arities_iter, layer_digest_and_optimal_layer_depth).enumerate()
		{
			let coset_index = index >> arity;

			log_n_cosets -= arity;

			let mut values = verify_coset_opening(
				self.vcs,
				coset_index,
				arity,
				optimal_layer_depth,
				log_n_cosets,
				layer,
				advice,
			)?;

			if next_value != values[index % (1 << arity)] {
				return Err(VerificationError::IncorrectFold {
					query_round: i,
					index,
				}
				.into());
			}

			next_value = fold_chunk(
				ntt,
				self.params.rs_code().log_len() - fold_round,
				coset_index,
				&mut values,
				&self.fold_challenges[fold_round..fold_round + arity],
			);
			index = coset_index;
			fold_round += arity;
		}

		if next_value != terminate_codeword[index] {
			return Err(VerificationError::IncorrectFold {
				query_round: self.n_oracles() - 1,
				index,
			}
			.into());
		}

		Ok(())
	}

	// scratch buffer used in `fold_chunk`.
	fn create_scratch_buffer(&self) -> Vec<F> {
		let max_arity = self
			.params
			.fold_arities()
			.iter()
			.copied()
			.max()
			.unwrap_or_default();
		let max_buffer_size = 2 * (1 << max_arity);
		vec![F::default(); max_buffer_size]
	}
}

/// Verifies that the coset opening provided in the proof is consistent with the VCS commitment.
#[allow(clippy::too_many_arguments)]
fn verify_coset_opening<F, MTScheme, B>(
	vcs: &MTScheme,
	coset_index: usize,
	log_coset_size: usize,
	optimal_layer_depth: usize,
	tree_depth: usize,
	layer_digests: &[MTScheme::Digest],
	advice: &mut TranscriptReader<B>,
) -> Result<Vec<F>, Error>
where
	F: BinaryField,
	MTScheme: MerkleTreeScheme<F>,
	B: Buf,
{
	let values = advice.read_scalar_slice::<F>(1 << log_coset_size)?;
	vcs.verify_opening(
		coset_index,
		&values,
		optimal_layer_depth,
		tree_depth,
		layer_digests,
		advice,
	)?;
	Ok(values)
}
