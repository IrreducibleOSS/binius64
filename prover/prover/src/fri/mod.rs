// Copyright 2025 Irreducible Inc.
use binius_field::{BinaryField, PackedField, is_packed_field_indexable};
use binius_math::{ReedSolomonCode, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript, TranscriptWriter,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::{
	checked_arithmetics::log2_strict_usize,
	rayon::iter::{IndexedParallelIterator, ParallelIterator},
};
#[allow(unused_imports)]
use binius_verifier::fri::FRIVerifier;
use binius_verifier::{
	fri::{
		FRIParams, RoundType,
		fold::{fold_chunk, fold_chunk_without_ntt},
	},
	hash::PseudoCompressionFunction,
};
use bytes::BufMut;
use digest::{Digest, Output, OutputSizeUser, core_api::BlockSizeUser};

use crate::merkle_tree::{BatchedMerkleTreeProver, MerkleTreeProver};

/// Provides the ability to run the batched FRI protocol from the prover side.
///
/// See [`FRIVerifier`] for information about the FRI protocol.
///
/// Generics:
/// - `F`: The field over which the protocol is executed.
/// - `H`, `C`: Choice of hashing and compression function, see [`MerkleTreeProver`].
/// - `NTT`: The NTT type used for encoding and folding.
///
/// Usage:
/// - To encode the messages (multilinear polynomials) and commit to them, use
///   [`Self::write_initial_commitment`]. \ This can be read by the verifier using
///   [`FRIVerifier::read_initial_commitment`].
/// - To provide the batch challenges, call [`Self::add_batch_challenges`]. This **must** be called
///   even if you only committed to a single message (in which case you should provide an empty
///   `Vec` of batch challenges).
/// - To run the COMMIT phase, call [`Self::prove_fold_round`] exactly [`Self::num_fold_rounds`]
///   many times. \ This can be observed by the verifier using [`FRIVerifier::verify_fold_round`].
/// - To run the QUERY phase, call [`Self::prove_queries`]. \ This can be checked by the verifier
///   using [`FRIVerifier::verify_queries`].
pub struct FRIProver<'a, F, H: OutputSizeUser, C, NTT> {
	params: &'a FRIParams<F, H, C>,
	ntt: &'a NTT,
	batched_initial_prover: BatchedMerkleTreeProver<F, H, C>,
	unprocessed_fold_challenges: Vec<F>,
	fold_provers: Vec<MerkleTreeProver<F, H, C>>,
	terminal_codeword: Option<Vec<F>>,
	fold_rounds_done: usize,
}

impl<'a, F, H, C, NTT> FRIProver<'a, F, H, C, NTT>
where
	F: BinaryField,
	H: Digest + BlockSizeUser + Sync,
	C: PseudoCompressionFunction<Output<H>, 2> + Sync,
	NTT: AdditiveNTT<Field = F> + Sync,
{
	/// Creates a prover instance which allows to run the FRI protocol.
	///
	/// Arguments:
	/// - `params`: Parameters used for the FRI protocol.
	/// - `ntt`: The NTT instance used for encoding and for folding.
	pub fn new(params: &'a FRIParams<F, H, C>, ntt: &'a NTT) -> Self {
		let (log_len, log_batch_size) = match *params.round_type(0) {
			RoundType::InitialCommitment {
				log_len,
				log_batch_size,
			} => (log_len, log_batch_size),
			_ => panic!("first round type mismatch"),
		};
		let batched_initial_prover = BatchedMerkleTreeProver::new(
			params.compression().clone(),
			log_len,
			log_batch_size,
			params.commit_layer(),
		);

		Self {
			params,
			ntt,
			batched_initial_prover,
			unprocessed_fold_challenges: Vec::new(),
			fold_provers: Vec::new(),
			terminal_codeword: None,
			fold_rounds_done: 0,
		}
	}

	/// Encodes a message (multilinear polynomial) and commits to it.
	///
	/// If the length of `poly` is less than the length of the FRI instance, then FRI will behave as
	/// if the polynomial was zero-padded (in an interleaved way) to the full length.
	///
	/// The counterpart on the verifier side is [`FRIVerifier::read_initial_commitment`].
	///
	/// Arguments:
	/// - `poly`: The multilinear polynomial that one wants to commit to, in Lagrange basis.
	/// - `transcript`: The [`TranscriptWriter`] used for writing the commitment.
	pub fn write_initial_commitment<P: PackedField<Scalar = F>>(
		&mut self,
		poly: &[P],
		transcript: &mut TranscriptWriter<impl BufMut>,
	) {
		assert_eq!(self.fold_rounds_done, 0);

		let (batched_log_len, batched_log_batch_size) = match *self.params.round_type(0) {
			RoundType::InitialCommitment {
				log_len,
				log_batch_size,
			} => (log_len, log_batch_size),
			_ => panic!("first round type mismatch"),
		};
		let log_inv_rate = self.params.rs_code().log_inv_rate();
		let log_len = log2_strict_usize(poly.len()) + log_inv_rate + P::LOG_WIDTH;
		assert!(log_len <= batched_log_len);
		let log_len_diff = batched_log_len - log_len;
		let log_batch_size = batched_log_batch_size.saturating_sub(log_len_diff);

		let subspace = self.ntt.subspace(log_len - log_batch_size);
		let rs_code = ReedSolomonCode::with_subspace(
			subspace,
			log_len - log_batch_size - log_inv_rate,
			log_inv_rate,
		)
		.unwrap();
		assert_eq!(rs_code.log_len(), log_len - log_batch_size);

		// encode poly to initial codeword
		assert_eq!(
			poly.len(),
			1 << (log_len - self.params.rs_code().log_inv_rate() - P::LOG_WIDTH)
		);
		let mut codeword: Vec<P> = Vec::with_capacity(1 << (log_len - P::LOG_WIDTH));
		rs_code
			.encode_batch(self.ntt, poly, codeword.spare_capacity_mut(), log_batch_size)
			.unwrap();
		unsafe {
			// SAFETY: encode_batch guarantees all elements are initialized on success
			codeword.set_len(1 << (log_len - P::LOG_WIDTH));
		}

		// convert `Vec<P>` to `Vec<F>`
		// Reason: Otherwise the merkle tree would need to be generic over P (or only own a slice of
		// the leaves and have a lifetime). How to do: Right now we just clone because we can't
		// use `Vec::from_raw_parts` due to alignment issues. Possible future solutions:
		// - make MerkleTreeProver just take a slice of the codeword (so FRIProver would need to
		//   store the leaves :/)
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
		self.batched_initial_prover
			.write_commitment(codeword, transcript);
	}

	/// Provide the batch challenges which are used for batching the initial codewords.
	///
	/// The number of challenges must be one less than the number of times you called
	/// [`Self::write_initial_commitment`].
	///
	/// The counterpart on the verifier side [`FRIVerifier::add_batch_challenges`].
	///
	/// Arguments:
	/// - `batch_challenges`: The batching challenges for the initial codewords (which should be
	///   sampled randomly).
	pub fn add_batch_challenges(&mut self, batch_challenges: Vec<F>) {
		self.batched_initial_prover
			.add_batch_challenges(batch_challenges);
	}

	/// The number of times [`Self::prove_fold_round`] must be called.
	pub fn num_fold_rounds(&self) -> usize {
		self.params.num_rounds() - 1
	}

	/// Proves a fold round of FRI in the COMMIT phase. Must be called [`Self::num_fold_rounds`]
	/// many times.
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
	/// - `transcript`: The [`TranscriptWriter`] which is used for writing the commitment (if there
	///   is one to make).
	pub fn prove_fold_round(
		&mut self,
		fold_challenge: F,
		transcript: &mut TranscriptWriter<impl BufMut>,
	) {
		self.unprocessed_fold_challenges.push(fold_challenge);

		match *self.params.round_type(self.fold_rounds_done + 1) {
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
				self.fold_provers.push(prover);
			}
			RoundType::TerminalCodeword { log_len } => {
				let codeword = self.fold_previous_codeword();
				assert_eq!(codeword.len(), 1 << log_len);

				transcript.write_slice(&codeword);
				self.terminal_codeword = Some(codeword);
			}
			_ => panic!("round type mismatch"),
		}

		self.fold_rounds_done += 1;
	}

	/// Internal function used for folding a codeword.
	fn fold_previous_codeword(&mut self) -> Vec<F> {
		let mut folded: Vec<F> = Vec::new();
		match self.fold_provers.len() {
			// in the first round we fold without applying the NTT
			0 => {
				let prover = &self.batched_initial_prover;
				let log_chunk_len = prover.log_batch_size();
				let create_scratch_buffer = || vec![F::default(); 1 << (log_chunk_len - 1)];
				prover
					.par_leaf_batches()
					.map_init(create_scratch_buffer, |scratch_buffer, chunk| {
						fold_chunk_without_ntt(
							chunk,
							&self.unprocessed_fold_challenges,
							scratch_buffer,
						)
					})
					.collect_into_vec(&mut folded);
			}
			// in all other rounds we fold normally
			_ => {
				let prover = self.fold_provers.last().unwrap();
				let log_len = prover.log_leaves();
				let log_chunk_len = prover.log_batch_size();
				let create_scratch_buffer = || vec![F::default(); 1 << (log_chunk_len - 1)];
				prover
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
					.collect_into_vec(&mut folded);
			}
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
	/// - `transcript`: The [`ProverTranscript`] used for sampling the query challenges and opening
	///   the commitments on the decommitment tape.
	pub fn prove_queries(&self, transcript: &mut ProverTranscript<impl Challenger>) {
		assert_eq!(self.fold_rounds_done, self.num_fold_rounds());

		let log_chunks =
			self.batched_initial_prover.log_leaves() - self.batched_initial_prover.log_batch_size();

		// prove the queries
		for _ in 0..self.params.num_queries() {
			// sample a random index
			let mut index = transcript.sample_bits(log_chunks) as usize;

			// open the merkle leaves at each layer
			self.batched_initial_prover
				.prove_opening(index, &mut transcript.decommitment());
			let mut fold_provers = self.fold_provers.iter();
			for i in 0..self.num_fold_rounds() {
				match self.params.round_type(i + 1) {
					RoundType::Vacant | RoundType::TerminalCodeword { .. } => {}
					RoundType::Commitment { log_batch_size, .. } => {
						index >>= log_batch_size;
						fold_provers
							.next()
							.unwrap()
							.prove_opening(index, &mut transcript.decommitment());
					}
					_ => panic!("round type mismatch"),
				}
			}
			assert!(fold_provers.next().is_none());
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

	fn test_with_params<P: PackedField>(polys: &[&[P]], params: &FRIParams<P::Scalar, H, C>)
	where
		P::Scalar: BinaryField,
	{
		// create prover transcript
		let challenger = StdChallenger::default();
		let mut prover_transcript = ProverTranscript::new(challenger);

		// prove
		{
			// prepare prover
			let domain_context =
				GenericPreExpanded::generate_from_subspace(params.rs_code().subspace());
			let ntt = NeighborsLastMultiThread::new(domain_context, 4);
			let mut fri_prover = FRIProver::new(params, &ntt);

			// commit
			for &poly in polys {
				fri_prover.write_initial_commitment(poly, &mut prover_transcript.message());
			}

			// batch
			let batch_challenges = prover_transcript.sample_vec(polys.len() - 1);
			fri_prover.add_batch_challenges(batch_challenges);

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

		// used for checking with `evaluate` later
		let mut verifier_fold_challenges: Vec<P::Scalar> = Vec::new();
		let verifier_batch_challenges: Vec<P::Scalar>;

		let final_value;
		// verify
		{
			// prepare verifier
			let domain_context =
				GenericOnTheFly::generate_from_subspace(params.rs_code().subspace());
			let mut fri_verifier = FRIVerifier::new(params, domain_context);

			// read commitment
			for i in 0..polys.len() {
				let log_poly_len = log2_strict_usize(polys[i].len()) + P::LOG_WIDTH;
				fri_verifier
					.read_initial_commitment(log_poly_len, &mut verifier_transcript.message());
			}

			// batch
			let batch_challenges = verifier_transcript.sample_vec(polys.len() - 1);
			verifier_batch_challenges = batch_challenges.clone();
			fri_verifier.add_batch_challenges(batch_challenges);

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

		let evaluations: Vec<P::Scalar> = polys
			.iter()
			.map(|poly| {
				let poly_buffer =
					FieldSlice::from_slice(log2_strict_usize(poly.len()) + P::LOG_WIDTH, poly)
						.unwrap();

				// NOTE: The interpretation when using a small multilinear in batched FRI is that it
				// behaves as if you had committed a big multilinear which is the zero-padded
				// version of the small multilinear as below. (Except that the FRI
				// implementation handles this in a cheaper way.)
				let batched_log_len = params.log_msg_len();
				let log_len_diff = batched_log_len - poly_buffer.log_len();
				let mut poly_zero_padded: Vec<P::Scalar> =
					vec![P::Scalar::zero(); 1 << batched_log_len];
				for i in 0..poly_buffer.len() {
					poly_zero_padded[i << log_len_diff] = poly_buffer.get(i).unwrap();
				}

				let poly_zero_padded_buffer =
					FieldSlice::from_slice(batched_log_len, &poly_zero_padded).unwrap();
				evaluate(&poly_zero_padded_buffer, &verifier_fold_challenges).unwrap()
			})
			.collect();
		let mut batched_evaluation = evaluations[0];
		assert_eq!(verifier_batch_challenges.len() + 1, evaluations.len());
		for (&evaluation, &batch_challenge) in evaluations[1..]
			.iter()
			.zip(verifier_batch_challenges.iter())
		{
			batched_evaluation += batch_challenge * evaluation;
		}
		assert_eq!(final_value, batched_evaluation);
	}

	fn test_with_config<P: PackedField>(
		polys: &[FieldBuffer<P>],
		commit_layer: usize,
		log_len: usize,
		fold_arities: Vec<usize>,
		log_inv_rate: usize,
	) where
		P::Scalar: BinaryField,
	{
		let num_queries = 5;
		let rs_code = ReedSolomonCode::new(log_len - fold_arities[0], log_inv_rate).unwrap();
		let params = FRIParams::new(
			StdCompression::default(),
			commit_layer,
			log_len,
			rs_code,
			fold_arities,
			num_queries,
		);

		let polys: Vec<_> = polys.iter().map(AsRef::as_ref).collect();
		test_with_params(&polys, &params);
	}

	fn test_with_packing<P: PackedField>()
	where
		P::Scalar: BinaryField,
	{
		let log_len = 6;

		// generate multilinears
		let mut rng = StdRng::seed_from_u64(0);
		let poly1 = random_field_buffer::<P>(&mut rng, log_len - 1);
		let poly2 = random_field_buffer::<P>(&mut rng, log_len);
		let poly3 = random_field_buffer::<P>(&mut rng, log_len - 3);
		let polys = vec![poly1, poly2, poly3];

		// check with different configs
		for log_inv_rate in [0, 1, 2] {
			for commit_layer in [0, 2, 1000] {
				test_with_config(&polys, commit_layer, log_len, vec![1; 6], log_inv_rate);
				test_with_config(&polys, commit_layer, log_len, vec![2, 2, 2], log_inv_rate);
				test_with_config(&polys, commit_layer, log_len, vec![3], log_inv_rate);
				test_with_config(&polys, commit_layer, log_len, vec![1, 3], log_inv_rate);
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
