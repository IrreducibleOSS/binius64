use std::marker::PhantomData;

use binius_core::{
	constraint_system::{
		AndConstraint, MulConstraint, Operand, ShiftVariant, ShiftedValueIndex, ValueVec,
	},
	word::Word,
};
use binius_field::{
	AESTowerField8b as B8, BinaryField, PackedAESBinaryField16x8b, PackedExtension, PackedField,
};
use binius_math::{
	BinarySubspace, FieldBuffer,
	ntt::{NeighborsLastMultiThread, domain_context::GenericPreExpanded},
	univariate::lagrange_evals,
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{SerializeBytes, checked_arithmetics::checked_log_2, rayon::prelude::*};
use binius_verifier::{
	Verifier,
	and_reduction::verifier::AndCheckOutput,
	config::{
		B1, B128, LOG_WORD_SIZE_BITS, LOG_WORDS_PER_ELEM, PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES,
	},
	hash::PseudoCompressionFunction,
	protocols::{intmul::IntMulOutput, sumcheck::SumcheckOutput},
};
use digest::{Digest, FixedOutputReset, Output, core_api::BlockSizeUser};
use itertools::izip;

use super::error::Error;
use crate::{
	and_reduction::{prover::OblongZerocheckProver, utils::multivariate::OneBitOblongMultilinear},
	fri,
	fri::CommitOutput,
	hash::ParallelDigest,
	merkle_tree::prover::BinaryMerkleTreeProver,
	pcs::OneBitPCSProver,
	protocols::{
		intmul::{prove::IntMulProver, witness::Witness as IntMulWitness},
		shift::{
			KeyCollection, OperatorData, build_key_collection, prove as prove_shift_reduction,
		},
	},
};

/// Struct for proving instances of a particular constraint system.
///
/// The [`Self::setup`] constructor pre-processes reusable structures for proving instances of the
/// given constraint system. Then [`Self::prove`] is called one or more times with individual
/// instances.
#[derive(Debug)]
pub struct Prover<P, MerkleCompress, ParallelMerkleHasher: ParallelDigest> {
	key_collection: KeyCollection,
	verifier: Verifier<ParallelMerkleHasher::Digest, MerkleCompress>,
	ntt: NeighborsLastMultiThread<GenericPreExpanded<B128>>,
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
		let key_collection = build_key_collection(verifier.constraint_system());

		let subspace = verifier.fri_params().rs_code().subspace();
		let domain_context = GenericPreExpanded::generate_from_subspace(subspace);
		// FIXME TODO For mobile phones, the number of shares should potentially be more than the
		// number of threads, because the threads/cores have different performance (but in the NTT
		// each share has the same amount of work)
		let log_num_shares = binius_utils::rayon::current_num_threads().ilog2() as usize;
		let ntt = NeighborsLastMultiThread {
			domain_context,
			log_num_shares,
		};

		let merkle_prover = BinaryMerkleTreeProver::<_, ParallelMerkleHasher, _>::new(
			verifier.merkle_scheme().compression().clone(),
		);

		Ok(Prover {
			key_collection,
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

		let _prove_guard = tracing::info_span!(
			"Prove",
			operation = "prove",
			perfetto_category = "operation",
			n_witness_words = cs.value_vec_layout.total_len,
			n_bitand = cs.and_constraints.len(),
			n_intmul = cs.mul_constraints.len(),
		)
		.entered();

		// [phase] Setup - initialization and constraint system setup
		let setup_guard =
			tracing::info_span!("[phase] Setup", phase = "setup", perfetto_category = "phase")
				.entered();
		let witness_packed = pack_witness::<P>(verifier.log_witness_elems(), &witness)?;
		drop(setup_guard);

		// [phase] Witness Commit - witness generation and commitment
		let witness_commit_guard = tracing::info_span!(
			"[phase] Witness Commit",
			phase = "witness_commit",
			perfetto_category = "phase"
		)
		.entered();
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
		drop(witness_commit_guard);

		// [phase] BitAnd Reduction - AND constraint reduction
		let bitand_guard = tracing::info_span!(
			"[phase] BitAnd Reduction",
			phase = "bitand_reduction",
			perfetto_category = "phase",
			n_constraints = cs.and_constraints.len()
		)
		.entered();
		let bitand_claim = {
			let bitand_witness =
				build_bitand_witness(&cs.and_constraints, witness.combined_witness());
			let AndCheckOutput {
				a_eval,
				b_eval,
				c_eval,
				z_challenge,
				eval_point,
			} = prove_bitand_reduction::<B128, _>(bitand_witness, transcript)?;
			OperatorData {
				evals: vec![a_eval, b_eval, c_eval],
				r_zhat_prime: z_challenge,
				r_x_prime: eval_point,
			}
		};
		drop(bitand_guard);

		// [phase] IntMul Reduction - multiplication constraint reduction
		let intmul_guard = tracing::info_span!(
			"[phase] IntMul Reduction",
			phase = "intmul_reduction",
			perfetto_category = "phase",
			n_constraints = cs.mul_constraints.len()
		)
		.entered();
		let intmul_claim = {
			let mul_witness = build_intmul_witness(&cs.mul_constraints, witness.combined_witness());
			let IntMulOutput {
				eval_point,
				a_evals,
				b_evals,
				c_lo_evals,
				c_hi_evals,
			} = prove_intmul_reduction::<_, P, _>(mul_witness, transcript)?;

			let z_challenge = transcript.sample();
			let subspace = BinarySubspace::<B8>::with_dim(LOG_WORD_SIZE_BITS)?.isomorphic();
			let l_tilde = lagrange_evals(&subspace, z_challenge);
			let make_final_claim = |evals| izip!(evals, &l_tilde).map(|(x, y)| x * y).sum();
			OperatorData {
				evals: vec![
					make_final_claim(a_evals),
					make_final_claim(b_evals),
					make_final_claim(c_lo_evals),
					make_final_claim(c_hi_evals),
				],
				r_zhat_prime: z_challenge,
				r_x_prime: eval_point,
			}
		};
		drop(intmul_guard);

		// [phase] Shift Reduction - shift operations
		let shift_guard = tracing::info_span!(
			"[phase] Shift Reduction",
			phase = "shift_reduction",
			perfetto_category = "phase"
		)
		.entered();
		let SumcheckOutput {
			challenges: eval_point,
			eval: _,
		} = prove_shift_reduction::<_, P, _>(
			verifier.log_public_words(),
			&self.key_collection,
			witness.combined_witness(),
			bitand_claim,
			intmul_claim,
			transcript,
		)?;
		drop(shift_guard);

		// [phase] PCS Opening - polynomial commitment opening
		let pcs_guard = tracing::info_span!(
			"[phase] PCS Opening",
			phase = "pcs_opening",
			perfetto_category = "phase"
		)
		.entered();
		let pcs_prover = OneBitPCSProver::new(witness_packed, eval_point);

		pcs_prover.prove_with_transcript(
			transcript,
			&self.ntt,
			&self.merkle_prover,
			verifier.fri_params(),
			&trace_codeword,
			&trace_committed,
		)?;
		drop(pcs_guard);

		Ok(())
	}
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

fn prove_bitand_reduction<F: BinaryField + From<B8>, Challenger_: Challenger>(
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

	let log_constraint_count = checked_log_2(a.len());

	// The structure of the AND reduction requires that it proves at least 2^3 word-level
	// constraints, you can zero-pad if necessary to reach this minimum
	assert!(log_constraint_count >= checked_log_2(binius_core::consts::MIN_AND_CONSTRAINTS));

	let big_field_zerocheck_challenges = transcript.sample_vec(log_constraint_count - 3);

	a.resize(1 << log_constraint_count, Word(0));
	b.resize(1 << log_constraint_count, Word(0));
	c.resize(1 << log_constraint_count, Word(0));

	let prover = OblongZerocheckProver::<_, PackedAESBinaryField16x8b>::new(
		OneBitOblongMultilinear {
			log_num_rows: log_constraint_count + LOG_WORD_SIZE_BITS,
			packed_evals: a,
		},
		OneBitOblongMultilinear {
			log_num_rows: log_constraint_count + LOG_WORD_SIZE_BITS,
			packed_evals: b,
		},
		OneBitOblongMultilinear {
			log_num_rows: log_constraint_count + LOG_WORD_SIZE_BITS,
			packed_evals: c,
		},
		big_field_zerocheck_challenges.to_vec(),
		PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES.to_vec(),
		prover_message_domain.isomorphic(),
	);

	Ok(prover.prove_with_transcript(transcript)?)
}

fn prove_intmul_reduction<F: BinaryField, P: PackedField<Scalar = F>, Challenger_: Challenger>(
	witness: MulCheckWitness,
	transcript: &mut ProverTranscript<Challenger_>,
) -> Result<IntMulOutput<F>, Error> {
	let MulCheckWitness { a, b, lo, hi } = witness;

	let mut mulcheck_prover = IntMulProver::new(0, transcript);

	// Words must be converted to u64 because
	// `Bitwise` requires `From<u8>` and `Shr<usize>`
	// We could implement these for `Word` in the future.
	let convert_to_u64 = |w: Vec<Word>| w.into_iter().map(|w| w.0).collect::<Vec<u64>>();
	let [a_u64, b_u64, lo_u64, hi_u64] = [a, b, lo, hi].map(convert_to_u64);
	let intmul_witness =
		IntMulWitness::<P, _, _>::new(LOG_WORD_SIZE_BITS, &a_u64, &b_u64, &lo_u64, &hi_u64)?;

	Ok(mulcheck_prover.prove(intmul_witness)?)
}

struct AndCheckWitness {
	a: Vec<Word>,
	b: Vec<Word>,
	c: Vec<Word>,
}

struct MulCheckWitness {
	a: Vec<Word>,
	b: Vec<Word>,
	lo: Vec<Word>,
	hi: Vec<Word>,
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
fn build_bitand_witness(and_constraints: &[AndConstraint], witness: &[Word]) -> AndCheckWitness {
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

#[tracing::instrument(skip_all, "Build IntMul witness", level = "debug")]
fn build_intmul_witness(mul_constraints: &[MulConstraint], witness: &[Word]) -> MulCheckWitness {
	let n_constraints = mul_constraints.len();

	let mut a = Vec::with_capacity(n_constraints);
	let mut b = Vec::with_capacity(n_constraints);
	let mut lo = Vec::with_capacity(n_constraints);
	let mut hi = Vec::with_capacity(n_constraints);

	(
		mul_constraints,
		a.spare_capacity_mut(),
		b.spare_capacity_mut(),
		lo.spare_capacity_mut(),
		hi.spare_capacity_mut(),
	)
		.into_par_iter()
		.for_each(|(constraint, a_i, b_i, lo_i, hi_i)| {
			a_i.write(build_operand_value(&constraint.a, witness));
			b_i.write(build_operand_value(&constraint.b, witness));
			lo_i.write(build_operand_value(&constraint.lo, witness));
			hi_i.write(build_operand_value(&constraint.hi, witness));
		});

	// Safety: all entries in a, b, lo, hi are initialized in the parallel loop above.
	unsafe {
		a.set_len(n_constraints);
		b.set_len(n_constraints);
		lo.set_len(n_constraints);
		hi.set_len(n_constraints);
	}

	MulCheckWitness { a, b, lo, hi }
}
