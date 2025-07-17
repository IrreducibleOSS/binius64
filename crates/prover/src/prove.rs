use binius_field::{Field, PackedExtension, PackedField};
use binius_frontend::{constraint_system::ValueVec, word::Word};
use binius_math::{FieldBuffer, ntt::AdditiveNTT};
use binius_maybe_rayon::{iter::repeatn, prelude::*};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::SerializeBytes;
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
	} = fri::commit_interleaved(
		params.fri_params().rs_code(),
		params.fri_params(),
		ntt,
		merkle_prover,
		witness_packed.as_ref(),
	)?;
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

	let witness_elems = witness.combined_witness().par_chunks(2).map(|chunk| {
		let word_0 = chunk.first().copied().expect("chunk cannot be empty");
		let word_1 = chunk.get(1).copied().unwrap_or(Word::ZERO);
		B128::new(((word_1.0 as u128) << 64) | (word_0.0 as u128))
	});
	let padded_witness_elems =
		witness_elems.chain(repeatn(B128::ZERO, (1 << log_witness_elems) - n_witness_elems));

	let witness_packed = padded_witness_elems
		.chunks(P::WIDTH)
		.map(|chunk| P::from_scalars(chunk))
		.collect::<Vec<_>>();
	debug_assert_eq!(witness_packed.len(), 1 << log_witness_elems.saturating_sub(P::LOG_WIDTH));

	let ret = FieldBuffer::new(log_witness_elems, witness_packed.into_boxed_slice())
		.expect("witness_packed length is correct by construction");
	Ok(ret)
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
