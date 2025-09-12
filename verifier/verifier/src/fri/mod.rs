// Copyright 2025 Irreducible Inc.
mod params;
use binius_math::ntt::DomainContext;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::checked_arithmetics::log2_strict_usize;
pub use params::*;
pub mod fold;

use binius_field::BinaryField;
use binius_transcript::TranscriptReader;
use bytes::Buf;
use digest::{Digest, Output, OutputSizeUser, core_api::BlockSizeUser};

use crate::{
	fri::fold::{fold_chunk_in_place, fold_chunk_without_ntt_in_place},
	hash::PseudoCompressionFunction,
	merkle_tree::MerkleTreeVerifier,
};

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
	#[error("the proof is invalid")]
	InvalidProof,
}

/// Provides the ability to run the FRI protocol from the verifier side.
///
/// This FRI implementation is special in the following ways:
/// - The folding arity can be bigger than 1, and can be non-constant (i.e. vary from round to
///   round).
/// - The folding is compatible with evaluation of a multilinear stored in Lagrange basis.
///   Concretely, the final value returned by [`Self::verify_queries`] is the evaluation of the
///   original message interpreted as a multilinear in Lagrange basis, at the point which is given
///   by the folding challenges.
/// - It's an _internal_ choice of this implementation how things are encoded, in particular whether
///   it uses "interleaved codewords" or not.
///
/// Generics:
/// - `F`: The field over which the protocol is executed.
/// - `H`, `C`: Choice of hashing and compression function, see [`MerkleTreeVerifier`].
/// - `NTT`: The NTT type used for encoding and folding.
///
/// Usage:
/// - To read the commitment to the initial codeword, use [`Self::read_initial_commitment`].
/// - To run the COMMIT phase, call [`Self::verify_fold_round`] exactly [`Self::num_fold_rounds`]
///   many times.
/// - To run the QUERY phase, call [`Self::verify_queries`].
pub struct FRIVerifier<'a, F, H: OutputSizeUser, C, DC> {
	params: &'a FRIParams<F, H, C>,
	domain_context: DC,
	fold_challenges: Vec<Vec<F>>,
	merkle_tree_verifiers: Vec<MerkleTreeVerifier<F, H, C>>,
	terminal_codeword: Option<Vec<F>>,
	rounds_done: usize,
}

impl<'a, F, H, C, DC> FRIVerifier<'a, F, H, C, DC>
where
	F: BinaryField,
	H: Digest + BlockSizeUser,
	C: PseudoCompressionFunction<Output<H>, 2>,
	DC: DomainContext<Field = F>,
{
	/// Creates a verifier instance which allows to run the FRI protocol.
	///
	/// Arguments:
	/// - `params`: Parameters used for the FRI protocol.
	/// - `domain_context`: The `DomainContext` instance used later for folding.
	pub fn new(params: &'a FRIParams<F, H, C>, domain_context: DC) -> Self {
		Self {
			params,
			domain_context,
			fold_challenges: vec![Vec::new()],
			merkle_tree_verifiers: Vec::new(),
			terminal_codeword: None,
			rounds_done: 0,
		}
	}

	/// Reads the FRI initial codeword commitment.
	///
	/// Arguments:
	/// - `transcript`: The [`TranscriptReader`] used for reading the commitment.
	pub fn read_initial_commitment(&mut self, transcript: &mut TranscriptReader<impl Buf>) {
		assert_eq!(self.rounds_done, 0);

		let (log_len, log_batch_size) = match *self.params.round_type(0) {
			RoundType::InitialCommitment {
				log_len,
				log_batch_size,
			} => (log_len, log_batch_size),
			_ => panic!("first round type mismatch"),
		};
		let initial_verifier = MerkleTreeVerifier::read_commitment(
			self.params.compression().clone(),
			log_len,
			log_batch_size,
			self.params.commit_layer(),
			transcript,
		);

		self.merkle_tree_verifiers.push(initial_verifier);
		self.rounds_done += 1;
	}

	/// The number of times [`Self::verify_fold_round`] must be called.
	pub fn num_fold_rounds(&self) -> usize {
		self.params.num_rounds() - 1
	}

	/// Verifies a fold round of FRI in the COMMIT phase. Must be called `Self::num_fold_rounds`
	/// many times.
	///
	/// Concretely, it does:
	/// - either nothing, if we skip this round because of a higher fold arity
	/// - or observes the commitment to the folded codeword
	/// - (if it's the last folding, it reads the full codeword instead of a commitment)
	///
	/// Arguments:
	/// - `fold_challenge`: The scalar used to fold the codeword (which should be sampled randomly).
	/// - `transcript`: The [`TranscriptReader`] which is used for reading the commitment (if there
	///   is one to observe).
	pub fn verify_fold_round(
		&mut self,
		challenge: F,
		transcript: &mut TranscriptReader<impl Buf>,
	) -> Result<(), VerificationError> {
		self.fold_challenges.last_mut().unwrap().push(challenge);

		match *self.params.round_type(self.rounds_done) {
			RoundType::Vacant => {}
			RoundType::Commitment {
				log_len,
				log_batch_size,
			} => {
				self.fold_challenges.push(Vec::new());
				let verifier = MerkleTreeVerifier::read_commitment(
					self.params.compression().clone(),
					log_len,
					log_batch_size,
					self.params.commit_layer(),
					transcript,
				);
				self.merkle_tree_verifiers.push(verifier);
			}
			RoundType::TerminalCodeword { log_len } => {
				self.fold_challenges.push(Vec::new());
				let terminal_codeword = transcript.read_vec(1 << log_len).unwrap();
				self.terminal_codeword = Some(terminal_codeword);
			}
			_ => panic!("round type mismatch"),
		}

		self.rounds_done += 1;

		Ok(())
	}

	/// Verifies the queries in the QUERY phase.
	///
	/// Concretely, for all queries, it:
	/// - samples the query challenge
	/// - read the respective openings on all the committed codewords
	/// - checks that the folding was done correctly
	///
	/// It also folds the terminal codeword and checks that it yields a constant codeword.
	/// It returns the value of this constant codeword, which equals the evaluation of the
	/// multilinear at the point given by the folding challenges.
	///
	/// Arguments:
	/// - `transcript`: The [`VerifierTranscript`] used for sampling the query challenges and
	///   reading openings on the decommitment tape.
	pub fn verify_queries(
		&mut self,
		transcript: &mut VerifierTranscript<impl Challenger>,
	) -> Result<F, VerificationError> {
		assert_eq!(self.rounds_done, self.params.num_rounds());

		let (fold_challenges_final, fold_challenges_early) =
			self.fold_challenges.split_last().unwrap();

		let log_chunks = self.merkle_tree_verifiers[0].log_leaf_batches();

		// verify the queries up to the terminal codeword
		let terminal_codeword = self.terminal_codeword.as_ref().unwrap();
		for _ in 0..self.params.num_queries() {
			// sample a random index
			let mut index = transcript.sample_bits(log_chunks) as usize;

			// verify openings of merkle leaves, and check that they fold together correctly
			let mut merkle_tree_verifiers = self.merkle_tree_verifiers.iter();
			let mut fold_challenges = fold_challenges_early.iter();
			let mut leaf_batch = merkle_tree_verifiers
				.next()
				.unwrap()
				.verify_opening(index, &mut transcript.decommitment())
				.unwrap();
			let mut folded_value =
				fold_chunk_without_ntt_in_place(&mut leaf_batch, fold_challenges.next().unwrap());
			for i in 1..self.params.num_rounds() {
				match *self.params.round_type(i) {
					RoundType::Vacant => {}
					RoundType::Commitment {
						log_len,
						log_batch_size,
					} => {
						let offset = index & ((1 << log_batch_size) - 1);
						index >>= log_batch_size;
						leaf_batch = merkle_tree_verifiers
							.next()
							.unwrap()
							.verify_opening(index, &mut transcript.decommitment())
							.unwrap();
						if leaf_batch[offset] != folded_value {
							return Err(VerificationError::InvalidProof);
						}
						folded_value = fold_chunk_in_place(
							&mut leaf_batch,
							fold_challenges.next().unwrap(),
							&self.domain_context,
							log_len,
							index,
						);
					}
					RoundType::TerminalCodeword { .. } => {
						if terminal_codeword[index] != folded_value {
							return Err(VerificationError::InvalidProof);
						}
					}
					_ => panic!("round type mismatch"),
				}
			}
			assert!(merkle_tree_verifiers.next().is_none());
			assert!(fold_challenges.next().is_none());
		}

		// fold terminal_codeword to final_codeword
		let terminal_codeword = self.terminal_codeword.as_mut().unwrap();
		let log_len = log2_strict_usize(terminal_codeword.len());
		let log_final_len = self.params.rs_code().log_inv_rate();
		let log_chunk_size = log_len - log_final_len;
		let final_codeword: Vec<F> = terminal_codeword
			.chunks_exact_mut(1 << log_chunk_size)
			.enumerate()
			.map(|(index, chunk)| {
				fold_chunk_in_place(
					chunk,
					fold_challenges_final,
					&self.domain_context,
					log_len,
					index,
				)
			})
			.collect();

		// check that final_codeword is constant
		assert_eq!(final_codeword.len(), 1 << log_final_len);
		let folded_value = final_codeword[0];
		for val in final_codeword {
			if val != folded_value {
				return Err(VerificationError::InvalidProof);
			}
		}

		Ok(folded_value)
	}
}
