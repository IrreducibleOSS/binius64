use binius_field::{PackedExtension, PackedField};
use binius_frontend::{constraint_system::ValueVec, word::Word};
use binius_math::{FieldBuffer, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{SerializeBytes, rayon::prelude::*};
use binius_verifier::{
	LOG_WORDS_PER_ELEM, Params, fields::B128, fri::FRIParams, merkle_tree::MerkleTreeScheme,
};

use super::error::Error;
use crate::{
	fri,
	fri::{CommitOutput, FRIFolder, FoldRoundOutput},
	merkle_tree::MerkleTreeProver,
};

#[allow(clippy::too_many_arguments)]
pub fn prove<P, Challenger_, NTT, MTScheme, MTProver>(
	params: &Params<MTScheme>,
	witness: ValueVec,
	transcript: &mut ProverTranscript<Challenger_>,
	ntt: &NTT,
	merkle_prover: &MTProver,
) -> Result<(), Error>
where
	P: PackedField<Scalar = B128> + PackedExtension<B128>,
	Challenger_: Challenger,
	NTT: AdditiveNTT<B128> + Sync,
	MTScheme: MerkleTreeScheme<B128>,
	MTScheme::Digest: SerializeBytes,
	MTProver: MerkleTreeProver<B128, Scheme = MTScheme>,
{
	let witness_packed = pack_witness::<P>(params.log_witness_elems(), witness)?;

	// Commit the witness.
	let CommitOutput {
		commitment: trace_commitment,
		committed: trace_committed,
		codeword: trace_codeword,
	} = fri::commit_interleaved(params.fri_params(), ntt, merkle_prover, witness_packed.to_ref())?;
	transcript.message().write(&trace_commitment);

	// Run the FRI proximity test protocol on the witness commitment.
	run_fri(params.fri_params(), ntt, merkle_prover, trace_codeword, trace_committed, transcript)?;
	Ok(())
}

fn pack_witness<P: PackedField<Scalar = B128>>(
	log_witness_elems: usize,
	witness: ValueVec,
) -> Result<FieldBuffer<P>, Error> {
	// The number of field elements that constitute the packed witness.
	let n_witness_elems = witness.size().div_ceil(1 << LOG_WORDS_PER_ELEM);
	if n_witness_elems > 1 << log_witness_elems {
		return Err(Error::ArgumentError {
			arg: "witness".to_string(),
			msg: "witness element count is incompatible with the constraint system".to_string(),
		});
	}

	let mut padded_witness_elems = FieldBuffer::zeros(log_witness_elems);
	let witness_elems = witness
		.combined_witness()
		.par_chunks(2 * P::WIDTH)
		.map(|chunk| {
			// Pack B128 elements into packed elements
			P::from_scalars(
				// Pack words into B128 elements
				chunk.chunks(2).map(|word_pair| {
					let word_0 = word_pair.first().copied().expect("chunk cannot be empty");
					let word_1 = word_pair.get(1).copied().unwrap_or(Word::ZERO);
					B128::new(((word_1.0 as u128) << 64) | (word_0.0 as u128))
				}),
			)
		});
	padded_witness_elems
		.as_mut()
		.par_iter_mut()
		.zip(witness_elems)
		.for_each(|(dst, elem)| *dst = elem);

	Ok(padded_witness_elems)
}

fn run_fri<P, Challenger_, NTT, MTScheme, MTProver>(
	params: &FRIParams<B128, B128>,
	ntt: &NTT,
	merkle_prover: &MTProver,
	codeword: Vec<P>,
	committed: MTProver::Committed,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<(), Error>
where
	P: PackedField<Scalar = B128>,
	Challenger_: Challenger,
	NTT: AdditiveNTT<B128> + Sync,
	MTScheme: MerkleTreeScheme<B128>,
	MTScheme::Digest: SerializeBytes,
	MTProver: MerkleTreeProver<B128, Scheme = MTScheme>,
{
	let mut round_prover = FRIFolder::new(params, ntt, merkle_prover, &codeword, &committed)?;

	let mut round_commitments = Vec::with_capacity(params.n_oracles());
	for _i in 0..params.n_fold_rounds() {
		let challenge = transcript.sample();
		let fold_round_output = round_prover.execute_fold_round(challenge)?;
		match fold_round_output {
			FoldRoundOutput::NoCommitment => {}
			FoldRoundOutput::Commitment(round_commitment) => {
				transcript.message().write(&round_commitment);
				round_commitments.push(round_commitment);
			}
		}
	}

	round_prover.finish_proof(transcript)?;
	Ok(())
}
