use binius_field::{ExtensionField, Field, PackedExtension, PackedField};
use binius_frontend::{constraint_system::ValueVec, word::Word};
use binius_math::{
	FieldBuffer, inner_product::inner_product, multilinear::eq::eq_ind_partial_eval,
	ntt::AdditiveNTT,
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{SerializeBytes, rayon::prelude::*};
use binius_verifier::{
	LOG_WORDS_PER_ELEM, Params,
	fields::{B1, B128},
	merkle_tree::MerkleTreeScheme,
};

use super::error::Error;
use crate::{fri, fri::CommitOutput, merkle_tree::MerkleTreeProver, pcs::prover::OneBitPCSProver};

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
	let witness_packed = pack_witness::<B128>(params.log_witness_elems(), witness)?;

	let log_witness_elems = params.log_witness_elems();

	// Commit the witness.
	let CommitOutput {
		commitment: trace_commitment,
		committed: trace_committed,
		codeword: trace_codeword,
	} = fri::commit_interleaved(params.fri_params(), ntt, merkle_prover, witness_packed.to_ref())?;
	transcript.message().write(&trace_commitment);

	// ! slow
	let lifted_small_field_mle =
		lift_small_to_large_field(&large_field_mle_to_small_field_mle::<B1, B128>(
			&witness_packed.as_ref().to_vec(),	
		));

	let small_field_log_n_vars = log_witness_elems + <B128 as ExtensionField<B1>>::LOG_DEGREE;

	let evaluation_point: Vec<B128> = transcript.sample_vec(small_field_log_n_vars);

	let evaluation = inner_product::<B128>(
		lifted_small_field_mle,
		eq_ind_partial_eval(&evaluation_point).as_ref().to_vec(),
	);

	transcript.message().write(&evaluation);

	let ring_switch_pcs_prover =
		OneBitPCSProver::new(witness_packed, evaluation, evaluation_point)?;

	ring_switch_pcs_prover.prove_with_transcript(
		transcript,
		ntt,
		merkle_prover,
		params.fri_params(),
		&trace_codeword,
		&trace_committed,
	)?;

	Ok(())
}

fn large_field_mle_to_small_field_mle<F, FE>(large_field_mle: &[FE]) -> Vec<F>
where
	F: Field,
	FE: Field + ExtensionField<F>,
{
	large_field_mle
		.iter()
		.flat_map(|elm| ExtensionField::<F>::iter_bases(elm))
		.collect()
}

fn lift_small_to_large_field<F, FE>(small_field_elms: &[F]) -> Vec<FE>
where
	F: Field,
	FE: Field + ExtensionField<F>,
{
	small_field_elms.iter().map(|&elm| FE::from(elm)).collect()
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
