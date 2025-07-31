use binius_field::{PackedExtension, PackedField};
use binius_frontend::{
	constraint_system::{
		AndConstraint, ConstraintSystem, Operand, ShiftVariant, ShiftedValueIndex, ValueVec,
	},
	word::Word,
};
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval, ntt::AdditiveNTT};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{SerializeBytes, rayon::prelude::*};
use binius_verifier::{
	Params,
	config::{B128, LOG_WORD_SIZE_BITS, LOG_WORDS_PER_ELEM},
	merkle_tree::MerkleTreeScheme,
};

use super::error::Error;
use crate::{
	fold_word::fold_words,
	fri,
	fri::CommitOutput,
	merkle_tree::MerkleTreeProver,
	pcs::prover::OneBitPCSProver,
	protocols::{
		InOutCheckProver,
		sumcheck::{ProveSingleOutput, prove_single_mlecheck},
	},
};

#[allow(clippy::too_many_arguments)]
pub fn prove<P, Challenger_, NTT, MTScheme, MTProver>(
	params: &Params<MTScheme>,
	cs: &ConstraintSystem,
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
	// Check that the public input length is correct
	let public = witness.public().to_vec();
	if public.len() != 1 << params.log_public_words() {
		return Err(Error::ArgumentError {
			arg: "witness".to_string(),
			msg: format!(
				"witness layout has {} words, expected {}",
				public.len(),
				1 << params.log_public_words()
			),
		});
	}

	// TODO: Pack witness using P, not B128
	let witness_packed = pack_witness::<B128>(params.log_witness_elems(), &witness)?;

	// Commit the witness.
	let CommitOutput {
		commitment: trace_commitment,
		committed: trace_committed,
		codeword: trace_codeword,
	} = fri::commit_interleaved(params.fri_params(), ntt, merkle_prover, witness_packed.to_ref())?;
	transcript.message().write(&trace_commitment);

	let _and_witness = build_and_check_witness(&cs.and_constraints, witness.combined_witness());

	// Sample a challenge point during the shift reduction.
	let z_challenge = transcript.sample_vec(LOG_WORD_SIZE_BITS);
	let public_input_challenge = transcript.sample_vec(params.log_public_words());

	let z_tensor = eq_ind_partial_eval(&z_challenge);
	let witness_z_folded = fold_words::<_, P>(witness.combined_witness(), z_tensor.as_ref());
	let public_z_folded = fold_words::<_, P>(&public, z_tensor.as_ref());

	let public_check_prover =
		InOutCheckProver::new(witness_z_folded, public_z_folded, &public_input_challenge)?;
	let ProveSingleOutput {
		multilinear_evals,
		challenges: mut y_challenge,
	} = prove_single_mlecheck(public_check_prover, transcript)?;

	y_challenge.reverse();

	// Public input check prover returns the witness evaluation.
	assert_eq!(multilinear_evals.len(), 1);
	let witness_eval = multilinear_evals[0];
	transcript.message().write(&witness_eval);

	// PCS opening
	let evaluation_point = [z_challenge, y_challenge].concat();
	let pcs_prover = OneBitPCSProver::new(witness_packed, witness_eval, evaluation_point)?;
	pcs_prover.prove_with_transcript(
		transcript,
		ntt,
		merkle_prover,
		params.fri_params(),
		&trace_codeword,
		&trace_committed,
	)?;

	Ok(())
}

fn pack_witness<P: PackedField<Scalar = B128>>(
	log_witness_elems: usize,
	witness: &ValueVec,
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


// TODO: This struct will be used in a future implementation of witness checking
#[allow(dead_code)]
struct AndCheckWitness {
	a: Vec<Word>,
	b: Vec<Word>,
	c: Vec<Word>,
}


#[inline]
fn build_operand_value(operand: &Operand, witness: &[Word]) -> Word {
	operand.iter().fold(
		Word::ZERO,
		|acc,
		 ShiftedValueIndex {
		     value_index,
		     shift_variant,
		     amount,
		 }| {
			let word = witness[value_index.0 as usize];
			let shifted_word = match shift_variant {
				ShiftVariant::Sll => word << (*amount as u32),
				ShiftVariant::Slr => word >> (*amount as u32),
				ShiftVariant::Sar => word.sar(*amount as u32),
			};
			acc ^ shifted_word
		},
	)
}

fn build_and_check_witness(and_constraints: &[AndConstraint], witness: &[Word]) -> AndCheckWitness {
	let n_constraints = and_constraints.len();

	let mut a = Vec::with_capacity(n_constraints);
	let mut b = Vec::with_capacity(n_constraints);
	let mut c = Vec::with_capacity(n_constraints);

	(and_constraints, a.spare_capacity_mut(), b.spare_capacity_mut(), c.spare_capacity_mut())
		.into_par_iter()
		.for_each(|(constraint, a_i, b_i, c_i)| {
			a_i.write(build_operand_value(&constraint.a, witness));
			b_i.write(build_operand_value(&constraint.b, witness));
			c_i.write(build_operand_value(&constraint.c, witness));
		});

	// Safety: all entries in a, b, c are initialized in the parallel loop above.
	unsafe {
		a.set_len(n_constraints);
		b.set_len(n_constraints);
		c.set_len(n_constraints);
	}

	AndCheckWitness { a, b, c }
}
