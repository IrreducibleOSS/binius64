use std::marker::PhantomData;

use binius_core::{
	constraint_system::{AndConstraint, Operand, ShiftVariant, ShiftedValueIndex, ValueVec},
	word::Word,
};
use binius_field::{
	AESTowerField8b as B8, BinaryField, PackedAESBinaryField16x8b, PackedExtension, PackedField,
};
use binius_math::{
	BinarySubspace, FieldBuffer,
	multilinear::eq::eq_ind_partial_eval,
	ntt::{MultiThreadedNTT, SingleThreadedNTT, twiddle::PrecomputedTwiddleAccess},
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{SerializeBytes, rayon::prelude::*};
use binius_verifier::{
	Verifier,
	config::{
		B1, B128, LOG_WORD_SIZE_BITS, LOG_WORDS_PER_ELEM, PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES,
	},
	hash::PseudoCompressionFunction,
};
use digest::{Digest, FixedOutputReset, Output, core_api::BlockSizeUser};

use super::error::Error;
use crate::{
	and_reduction::{prover::OblongZerocheckProver, utils::multivariate::OneBitOblongMultilinear},
	fold_word::fold_words,
	fri,
	fri::CommitOutput,
	hash::ParallelDigest,
	merkle_tree::prover::BinaryMerkleTreeProver,
	pcs::prover::OneBitPCSProver,
	protocols::{
		InOutCheckProver,
		sumcheck::{ProveSingleOutput, prove_single_mlecheck},
	},
};

/// Struct for proving instances of a particular constraint system.
///
/// The [`Self::setup`] constructor pre-processes reusable structures for proving instances of the
/// given constraint system. Then [`Self::prove`] is called one or more times with individual
/// instances.
#[derive(Debug)]
pub struct Prover<P, MerkleCompress, ParallelMerkleHasher: ParallelDigest> {
	verifier: Verifier<ParallelMerkleHasher::Digest, MerkleCompress>,
	ntt: MultiThreadedNTT<B128, PrecomputedTwiddleAccess<B128>>,
	merkle_prover: BinaryMerkleTreeProver<B128, ParallelMerkleHasher, MerkleCompress>,
	_p_marker: PhantomData<P>,
}

impl<P, MerkleHash, MerkleCompress, ParallelMerkleHasher>
	Prover<P, MerkleCompress, ParallelMerkleHasher>
where
	P: PackedField<Scalar = B128> + PackedExtension<B128> + PackedExtension<B1>,
	MerkleHash: Digest + BlockSizeUser + FixedOutputReset,
	ParallelMerkleHasher: ParallelDigest<Digest = MerkleHash>,
	MerkleCompress: PseudoCompressionFunction<Output<MerkleHash>, 2> + Sync,
	Output<MerkleHash>: SerializeBytes,
{
	/// Constructs a prover corresponding to a constraint system verifier.
	///
	/// See [`Prover`] struct documentation for details.
	pub fn setup(verifier: Verifier<MerkleHash, MerkleCompress>) -> Result<Self, Error> {
		let ntt = SingleThreadedNTT::with_subspace(verifier.fri_params().rs_code().subspace())?
			.precompute_twiddles()
			.multithreaded();
		let merkle_prover = BinaryMerkleTreeProver::<_, ParallelMerkleHasher, _>::new(
			verifier.merkle_scheme().compression().clone(),
		);

		Ok(Prover {
			verifier,
			ntt,
			merkle_prover,
			_p_marker: PhantomData,
		})
	}

	pub fn prove<Challenger_: Challenger>(
		&self,
		witness: ValueVec,
		transcript: &mut ProverTranscript<Challenger_>,
	) -> Result<(), Error> {
		let verifier = &self.verifier;
		let cs = self.verifier.constraint_system();

		// Check that the public input length is correct
		let public = witness.public().to_vec();
		if public.len() != 1 << self.verifier.log_public_words() {
			return Err(Error::ArgumentError {
				arg: "witness".to_string(),
				msg: format!(
					"witness layout has {} words, expected {}",
					public.len(),
					1 << verifier.log_public_words()
				),
			});
		}

		let _scope = tracing::debug_span!(
			"Prover::prove",
			n_witness_words = cs.value_vec_layout.total_len,
			n_bitand = cs.and_constraints.len(),
			n_intmul = cs.mul_constraints.len(),
		)
		.entered();

		let witness_packed = pack_witness::<P>(verifier.log_witness_elems(), &witness)?;

		// Commit the witness.
		let CommitOutput {
			commitment: trace_commitment,
			committed: trace_committed,
			codeword: trace_codeword,
		} = fri::commit_interleaved(
			verifier.fri_params(),
			&self.ntt,
			&self.merkle_prover,
			witness_packed.to_ref(),
		)?;
		transcript.message().write(&trace_commitment);

		let andcheck_scope =
			tracing::debug_span!("BitAnd check", n_constraints = cs.and_constraints.len())
				.entered();
		let and_witness = build_and_check_witness(&cs.and_constraints, witness.combined_witness());
		let _output =
			run_and_check::<B128, _>(verifier.log_witness_words(), and_witness, transcript)?;
		drop(andcheck_scope);

		// Sample a challenge point during the shift reduction.
		let z_challenge = transcript.sample_vec(LOG_WORD_SIZE_BITS);
		let public_input_challenge = transcript.sample_vec(verifier.log_public_words());

		let pubcheck_scope =
			tracing::debug_span!("Public input check", n_public = 1 << verifier.log_public_words())
				.entered();

		let z_tensor = eq_ind_partial_eval(&z_challenge);
		let witness_z_folded = fold_words::<_, P>(witness.combined_witness(), z_tensor.as_ref());
		let public_z_folded = fold_words::<_, P>(&public, z_tensor.as_ref());

		let pubcheck_mlecheck_scope = tracing::debug_span!("Public input MLE-check").entered();
		let public_check_prover =
			InOutCheckProver::new(witness_z_folded, public_z_folded, &public_input_challenge)?;
		let ProveSingleOutput {
			multilinear_evals,
			challenges: mut y_challenge,
		} = prove_single_mlecheck(public_check_prover, transcript)?;
		drop(pubcheck_mlecheck_scope);

		y_challenge.reverse();

		// Public input check prover returns the witness evaluation.
		assert_eq!(multilinear_evals.len(), 1);
		let witness_eval = multilinear_evals[0];
		transcript.message().write(&witness_eval);
		drop(pubcheck_scope);

		// PCS opening
		let evaluation_point = [z_challenge, y_challenge].concat();

		// Convert witness_packed to PackedSubfield view for OneBitPCSProver
		let witness_packed_subfield_buffer = cast_bases_to_buffer(&witness_packed);

		let _scope = tracing::debug_span!("PCS open").entered();
		let pcs_prover =
			OneBitPCSProver::new(witness_packed_subfield_buffer, witness_eval, evaluation_point)?;

		pcs_prover.prove_with_transcript(
			transcript,
			&self.ntt,
			&self.merkle_prover,
			verifier.fri_params(),
			&trace_codeword,
			&trace_committed,
		)?;

		Ok(())
	}
}

/// Helper function to convert cast_bases result to FieldBuffer
fn cast_bases_to_buffer<P>(
	packed: &FieldBuffer<P>,
) -> FieldBuffer<<P as PackedExtension<B1>>::PackedSubfield>
where
	P: PackedExtension<B1>,
{
	let subfield = <P as PackedExtension<B1>>::cast_bases(packed.as_ref());
	let values: Vec<_> = subfield.iter().flat_map(|p| p.iter()).collect();
	FieldBuffer::from_values(&values).expect("cast_bases should produce power-of-2 length")
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

fn run_and_check<F: BinaryField + From<B8>, Challenger_: Challenger>(
	log_witness_words: usize,
	witness: AndCheckWitness,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<AndCheckOutput<F>, Error> {
	let prover_message_domain = BinarySubspace::<B8>::with_dim(LOG_WORD_SIZE_BITS + 1)
		.expect("B8::DEGREE is at least LOG_WORD_SIZE_BITS + 1");
	let AndCheckWitness {
		mut a,
		mut b,
		mut c,
	} = witness;

	// The structure of the AND reduction requires that it proves at least 2^3 word-level
	// constraints, you can zero-pad if necessary to reach this minimum
	assert!(log_witness_words >= 3);

	let big_field_zerocheck_challenges = transcript.sample_vec(log_witness_words - 3);

	a.resize(1 << log_witness_words, Word(0));
	b.resize(1 << log_witness_words, Word(0));
	c.resize(1 << log_witness_words, Word(0));

	let prover = OblongZerocheckProver::<_, PackedAESBinaryField16x8b>::new(
		OneBitOblongMultilinear {
			log_num_rows: log_witness_words + LOG_WORD_SIZE_BITS,
			packed_evals: a,
		},
		OneBitOblongMultilinear {
			log_num_rows: log_witness_words + LOG_WORD_SIZE_BITS,
			packed_evals: b,
		},
		OneBitOblongMultilinear {
			log_num_rows: log_witness_words + LOG_WORD_SIZE_BITS,
			packed_evals: c,
		},
		big_field_zerocheck_challenges.to_vec(),
		PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES.to_vec(),
		prover_message_domain.isomorphic(),
	);

	let prove_output = prover.prove_with_transcript(transcript)?;

	let mle_claims = prove_output.sumcheck_output.multilinear_evals;

	let l2h_query_for_evaluation_point = prove_output
		.sumcheck_output
		.challenges
		.clone()
		.into_iter()
		.rev()
		.collect::<Vec<_>>();

	transcript.message().write_slice(&mle_claims);
	Ok(AndCheckOutput {
		a_eval: mle_claims[0],
		b_eval: mle_claims[1],
		c_eval: mle_claims[2],
		z_challenge: prove_output.univariate_sumcheck_challenge,
		eval_point: l2h_query_for_evaluation_point,
	})
}

struct AndCheckWitness {
	a: Vec<Word>,
	b: Vec<Word>,
	c: Vec<Word>,
}

// These fields will be read once the shift reduction is used to prove these claims against the
// witness
#[allow(dead_code)]
struct AndCheckOutput<F> {
	a_eval: F,
	b_eval: F,
	c_eval: F,
	/// The challenge for the bit-index variable.
	z_challenge: F,
	/// Evaluation point of the word-index variables.
	eval_point: Vec<F>,
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

#[tracing::instrument(skip_all, "Build BitAnd witness", level = "debug")]
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
