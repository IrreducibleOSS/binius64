use binius_field::{BinaryField, PackedField, is_packed_field_indexable};
use binius_math::ntt::AdditiveNTT;
use binius_transcript::{
	ProverTranscript, TranscriptWriter,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::rayon::iter::{IndexedParallelIterator, ParallelIterator};
use binius_verifier::{
	fri2::{
		FRIParams, RoundType,
		fold::{fold_chunk, fold_chunk_without_ntt},
	},
	hash::PseudoCompressionFunction,
};
use bytes::BufMut;
use digest::{Digest, Output, OutputSizeUser, core_api::BlockSizeUser};

use crate::merkle_tree2::MerkleTreeProver;

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
		let mut codeword = Vec::with_capacity(1 << (log_len - P::LOG_WIDTH));
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

	pub fn num_fold_rounds(&self) -> usize {
		self.params.num_rounds() - 1
	}

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
