use binius_field::{BinaryField, PackedField, is_packed_field_indexable};
use binius_math::ntt::AdditiveNTT;
use binius_transcript::{
	ProverTranscript, TranscriptWriter,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::rayon::iter::{IndexedParallelIterator, ParallelIterator};
use binius_verifier::{
	fri2::{
		FRIParams, FRIVerifier, RoundType,
		fold::{fold_chunk, fold_chunk_without_ntt},
	},
	hash::PseudoCompressionFunction,
};
use bytes::BufMut;
use digest::{Digest, Output, OutputSizeUser, core_api::BlockSizeUser};

use crate::merkle_tree2::MerkleTreeProver;

/// Provides the ability to run the FRI protocol from the prover side.
///
/// See [`FRIVerifier`] for information about the FRI protocol.
///
/// Generics:
/// - `F`: The field over which the protocol is executed.
/// - `H`, `C`: Choice of hashing and compression function, see [`MerkleTreeProver`].
/// - `NTT`: The NTT type used for encoding and folding.
///
/// Usage:
/// - To encode the message (multilinear polynomial) and commit to it, use [`Self::write_initial_commitment`]. \
///   This can be read by the verifier using [`FRIVerifier::read_initial_commitment`].
/// - To run the COMMMIT phase, call [`Self::prove_fold_round`] exactly [`Self::num_fold_rounds`] many times. \
///   This can be observed by the verifier using [`FRIVerifier::verify_fold_round`].
/// - To run the QUERY phase, call [`Self::prove_queries`]. \
///   This can be checked by the verifier using [`FRIVerifier::verify_queries`].
pub struct FRIProver<'a, F, H: OutputSizeUser, C, NTT> {
	params: &'a FRIParams<F, H, C>,
	ntt: &'a NTT,
	unprocessed_fold_challenges: Vec<F>,
	merkle_tree_provers: Vec<MerkleTreeProver<F, H, C>>,
	terminal_codeword: Option<Vec<F>>,
	rounds_done: usize,
}

impl<'a, F, H, C, NTT> FRIProver<'a, F, H, C, NTT>
where
	F: BinaryField,
	H: Digest + BlockSizeUser + Sync,
	C: PseudoCompressionFunction<Output<H>, 2> + Sync,
	NTT: AdditiveNTT<Field = F> + Sync,
{
	/// Encodes the message (multilinear polynomial) and commits to it. Returns a prover instance which allows to run the FRI protocol on the codeword.
	///
	/// The counterpart on the verifier side is [`FRIVerifier::read_initial_commitment`].
	///
	/// Arguments:
	/// - `params`: Parameters used for the FRI protocol.
	/// - `poly`: The multilinear polynomial that one wants to commit to, in Lagrange basis.
	/// - `ntt`: The NTT instance used for encoding, and later for folding.
	/// - `transcript`: The [`TranscriptWriter`] used for writing the commitment.
	pub fn write_initial_commitment<P: PackedField<Scalar = F>>(
		params: &'a FRIParams<F, H, C>,
		poly: &[P],
		ntt: &'a NTT,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) -> Self {
		let (log_len, log_batch_size) = match *params.round_type(0) {
			RoundType::InitialCommitment {
				log_len,
				log_batch_size,
			} => (log_len, log_batch_size),
			_ => panic!("first round type mismatch"),
		};

		// encode poly to initial codeword
		assert_eq!(poly.len(), 1 << (log_len - params.rs_code().log_inv_rate() - P::LOG_WIDTH));
		let mut codeword: Vec<P> = Vec::with_capacity(1 << (log_len - P::LOG_WIDTH));
		params
			.rs_code()
			.encode_batch(ntt, poly, codeword.spare_capacity_mut(), log_batch_size)
			.unwrap();
		unsafe {
			// SAFETY: encode_batch guarantees all elements are initialized on success
			codeword.set_len(1 << (log_len - P::LOG_WIDTH));
		}

		// convert `Vec<P>` to `Vec<F>`
		// Reason: Otherwise the merkle tree would need to be generic over P (or only own a slice of the leaves and have a lifetime).
		// How to do: Right now we just clone because we can't use `Vec::from_raw_parts` due to alignment issues. Possible future solutions:
		// - make MerkleTreeProver just take a slice of the codeword (so FRIProver would need to store the leaves :/)
		// - use Box<[T]> in MerkleTreeProver which I think doesn't have the alignment problems
		// - implement something on FieldBuffer which supports this transformation
		let codeword: Vec<F> = match is_packed_field_indexable::<P>() {
			true => {
				let packed_slice: &[P] = codeword.as_ref();
				let scalar_slice = unsafe {
					std::slice::from_raw_parts(
						packed_slice.as_ptr() as *const P::Scalar,
						packed_slice.len() << P::LOG_WIDTH,
					)
				};
				scalar_slice.to_vec()
			}
			false => codeword.iter().flat_map(|p| p.iter()).collect(),
		};
		assert_eq!(codeword.len(), 1 << log_len);

		// commit initial codeword
		let initial_prover = MerkleTreeProver::write_commitment(
			params.compression().clone(),
			codeword,
			log_batch_size,
			params.commit_layer(),
			transcript,
		);

		Self {
			params,
			ntt,
			unprocessed_fold_challenges: Vec::new(),
			merkle_tree_provers: vec![initial_prover],
			terminal_codeword: None,
			rounds_done: 1,
		}
	}

	/// The number of times [`Self::prove_fold_round`] must be called.
	pub fn num_fold_rounds(&self) -> usize {
		self.params.num_rounds() - 1
	}

	/// Proves a fold round of FRI in the COMMIT phase. Must be called `Self::num_fold_rounds` many times.
	///
	/// Concretely, it does:
	/// - either nothing, if we skip this round because of a higher fold arity
	/// - or folds the previously committed codeword and commits to it
	/// - (if it's the last folding, it writes the full codeword instead of a commitment)
	///
	/// The counterpart on the verifier side is [`FRIVerifier::verify_fold_round`].
	///
	/// Arguments:
	/// - `fold_challenge`: The scalar used to fold the codeword (which should be sampled randomly).
	/// - `transcript`: The [`TranscriptWriter`] which is used for writing the commitment (if there is one to make).
	pub fn prove_fold_round(
		&mut self,
		fold_challenge: F,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) {
		self.unprocessed_fold_challenges.push(fold_challenge);

		match *self.params.round_type(self.rounds_done) {
			RoundType::Vacant => {}
			RoundType::Commitment {
				log_len,
				log_batch_size,
			} => {
				let codeword = self.fold_previous_codeword();
				assert_eq!(codeword.len(), 1 << log_len);

				let prover = MerkleTreeProver::write_commitment(
					self.params.compression().clone(),
					codeword,
					log_batch_size,
					self.params.commit_layer(),
					transcript,
				);
				self.merkle_tree_provers.push(prover);
			}
			RoundType::TerminalCodeword { log_len } => {
				let codeword = self.fold_previous_codeword();
				assert_eq!(codeword.len(), 1 << log_len);

				transcript.write_slice(&codeword);
				self.terminal_codeword = Some(codeword);
			}
			_ => panic!("round type mismatch"),
		}

		self.rounds_done += 1;
	}

	/// Internal function used for folding a codeword.
	fn fold_previous_codeword(&mut self) -> Vec<F> {
		let prover = self.merkle_tree_provers.last().unwrap();
		let log_len = prover.log_leaves();
		let log_chunk_len = prover.log_batch_size();

		let create_scratch_buffer = || vec![F::default(); 1 << (log_chunk_len - 1)];
		let mut folded: Vec<F> = Vec::new();

		match self.merkle_tree_provers.len() {
			// in the first round we fold without applying the NTT
			1 => prover
				.par_leaf_batches()
				.map_init(create_scratch_buffer, |scratch_buffer, chunk| {
					fold_chunk_without_ntt(chunk, &self.unprocessed_fold_challenges, scratch_buffer)
				})
				.collect_into_vec(&mut folded),
			// in all other rounds we fold normally
			_ => prover
				.par_leaf_batches()
				.enumerate()
				.map_init(create_scratch_buffer, |scratch_buffer, (chunk_index, chunk)| {
					fold_chunk(
						chunk,
						&self.unprocessed_fold_challenges,
						self.ntt.domain_context(),
						log_len,
						chunk_index,
						scratch_buffer,
					)
				})
				.collect_into_vec(&mut folded),
		};
		self.unprocessed_fold_challenges.clear();

		folded
	}

	/// Proves the queries in the QUERY phase.
	///
	/// Concretely, for all queries, it:
	/// - samples the query challenge
	/// - opens the respective commitments on all the committed codewords
	///
	/// The counterpart on the verifier side is [`FRIVerifier::verify_queries`].
	///
	/// Arguments:
	/// - `transcript`: The [`ProverTranscript`] used for sampling the query challenges and opening the commitments on the decommitment tape.
	pub fn prove_queries(&self, transcript: &mut ProverTranscript<impl Challenger>) {
		assert_eq!(self.rounds_done, self.params.num_rounds());

		// prove the queries
		for _ in 0..self.params.num_queries() {
			// sample a random index
			let log_chunks = self.merkle_tree_provers[0].log_leaves()
				- self.merkle_tree_provers[0].log_batch_size();
			let mut index = transcript.sample_bits(log_chunks) as usize;

			// open the merkle leaves at each layer
			let mut merkle_tree_provers = self.merkle_tree_provers.iter();
			merkle_tree_provers
				.next()
				.unwrap()
				.prove_opening(index, &mut transcript.decommitment());
			for i in 1..self.params.num_rounds() {
				match self.params.round_type(i) {
					RoundType::Vacant | RoundType::TerminalCodeword { .. } => {}
					RoundType::Commitment { log_batch_size, .. } => {
						index >>= log_batch_size;
						merkle_tree_provers
							.next()
							.unwrap()
							.prove_opening(index, &mut transcript.decommitment());
					}
					_ => panic!("round type mismatch"),
				}
			}
			assert!(merkle_tree_provers.next().is_none());
		}
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{PackedBinaryGhash1x128b, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b};
	use binius_math::{
		FieldBuffer, FieldSlice, ReedSolomonCode,
		multilinear::evaluate::evaluate,
		ntt::{
			NeighborsLastMultiThread,
			domain_context::{GenericOnTheFly, GenericPreExpanded},
		},
		test_utils::random_field_buffer,
	};
	use binius_transcript::fiat_shamir::CanSample;
	use binius_utils::checked_arithmetics::log2_strict_usize;
	use binius_verifier::{
		config::StdChallenger,
		hash::{StdCompression, StdDigest},
	};
	use rand::prelude::*;

	use super::*;

	type H = StdDigest;
	type C = StdCompression;

	fn test_with_params<P: PackedField>(poly: &[P], params: &FRIParams<P::Scalar, H, C>)
	where
		P::Scalar: BinaryField,
	{
		// create prover transcipt
		let challenger = StdChallenger::default();
		let mut prover_transcript = ProverTranscript::new(challenger);

		// prove
		{
			// prepare prover
			let domain_context =
				GenericPreExpanded::generate_from_subspace(params.rs_code().subspace());
			let ntt = NeighborsLastMultiThread::new(domain_context, 4);

			// commit
			let mut fri_prover = FRIProver::write_initial_commitment(
				params,
				poly,
				&ntt,
				&mut prover_transcript.message(),
			);

			// prove COMMIT phase
			for _ in 0..fri_prover.num_fold_rounds() {
				let fold_challenge = prover_transcript.sample();
				fri_prover.prove_fold_round(fold_challenge, &mut prover_transcript.message());
			}

			// prove QUERY phase
			fri_prover.prove_queries(&mut prover_transcript);
		}

		// create verifier transcript
		let mut verifier_transcript = prover_transcript.into_verifier();

		// used for calling `evaluate` later
		let mut verifier_fold_challenges = Vec::new();

		let final_value;
		// verify
		{
			// prepare verifier
			let domain_context =
				GenericOnTheFly::generate_from_subspace(params.rs_code().subspace());

			// read commitment
			let mut fri_verifier = FRIVerifier::read_initial_commitment(
				params,
				domain_context,
				&mut verifier_transcript.message(),
			);

			// verify COMMIT phase
			for _ in 0..fri_verifier.num_fold_rounds() {
				let fold_challenge = verifier_transcript.sample();
				verifier_fold_challenges.push(fold_challenge);
				fri_verifier
					.verify_fold_round(fold_challenge, &mut verifier_transcript.message())
					.unwrap();
			}

			// verify QUERY phase
			final_value = fri_verifier
				.verify_queries(&mut verifier_transcript)
				.unwrap();
		}

		let poly_buffer =
			FieldSlice::from_slice(log2_strict_usize(poly.len()) + P::LOG_WIDTH, poly).unwrap();
		let evaluation = evaluate(&poly_buffer, &verifier_fold_challenges).unwrap();
		assert_eq!(final_value, evaluation);
	}

	fn test_with_config<P: PackedField>(
		poly: &FieldBuffer<P>,
		fold_arities: Vec<usize>,
		log_inv_rate: usize,
		commit_layer: usize,
	) where
		P::Scalar: BinaryField,
	{
		let num_queries = 5;
		let rs_code = ReedSolomonCode::new(poly.log_len() - fold_arities[0], log_inv_rate).unwrap();
		let params = FRIParams::new(
			StdCompression::default(),
			rs_code,
			fold_arities,
			num_queries,
			commit_layer,
		);

		test_with_params(poly.as_ref(), &params);
	}

	fn test_with_packing<P: PackedField>()
	where
		P::Scalar: BinaryField,
	{
		let log_len = 6;

		// generate multilinear
		let mut rng = StdRng::seed_from_u64(0);
		let poly = random_field_buffer::<P>(&mut rng, log_len);

		// check for different configs
		for log_inv_rate in [0, 1, 2] {
			for commit_layer in [0, 2, 1000] {
				test_with_config(&poly, vec![1; 6], log_inv_rate, commit_layer);
				test_with_config(&poly, vec![2, 2, 2], log_inv_rate, commit_layer);
				test_with_config(&poly, vec![3], log_inv_rate, commit_layer);
				test_with_config(&poly, vec![1, 3], log_inv_rate, commit_layer);
			}
		}
	}

	#[test]
	fn test_ghash() {
		test_with_packing::<PackedBinaryGhash1x128b>();
		test_with_packing::<PackedBinaryGhash2x128b>();
		test_with_packing::<PackedBinaryGhash4x128b>();
	}
}
