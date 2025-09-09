mod params;
use binius_math::ntt::DomainContext;
use binius_transcript::VerifierTranscript;
use binius_transcript::fiat_shamir::CanSampleBits;
use binius_transcript::fiat_shamir::Challenger;
use binius_utils::checked_arithmetics::log2_strict_usize;
pub use params::*;
pub mod fold;

use binius_field::BinaryField;
use binius_transcript::TranscriptReader;
use bytes::Buf;
use digest::Digest;
use digest::Output;
use digest::OutputSizeUser;
use digest::core_api::BlockSizeUser;

use crate::fri2::fold::fold_chunk_in_place;
use crate::fri2::fold::fold_chunk_without_ntt_in_place;
use crate::hash::PseudoCompressionFunction;
use crate::merkle_tree2::MerkleTreeVerifier;

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
	#[error("the proof is invalid")]
	InvalidProof,
}

/// Verifier for the FRI "COMMIT" phase.
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
	pub fn read_initial_commitment(
		params: &'a FRIParams<F, H, C>,
		domain_context: DC,
		transcript: &mut TranscriptReader<impl Buf>,
	) -> Self {
		let (log_len, log_batch_size) = match *params.round_type(0) {
			RoundType::InitialCommitment {
				log_len,
				log_batch_size,
			} => (log_len, log_batch_size),
			_ => panic!("first round type mismatch"),
		};
		let initial_verifier = MerkleTreeVerifier::read_commitment(
			params.compression().clone(),
			log_len,
			log_batch_size,
			params.commit_layer(),
			transcript,
		);

		Self {
			params,
			domain_context,
			fold_challenges: vec![Vec::new()],
			merkle_tree_verifiers: vec![initial_verifier],
			terminal_codeword: None,
			rounds_done: 1,
		}
	}

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
				println!("terminal_codeword={terminal_codeword:?}");
				self.terminal_codeword = Some(terminal_codeword);
			}
			_ => panic!("round type mismatch"),
		}

		self.rounds_done += 1;

		Ok(())
	}

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

		// check terminal codeword
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
		assert_eq!(final_codeword.len(), 1 << log_final_len);
		let folded_value = final_codeword[0];
		// check that the final_codeword is constant
		for val in final_codeword {
			if val != folded_value {
				return Err(VerificationError::InvalidProof);
			}
		}

		Ok(folded_value)
	}
}
