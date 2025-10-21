// Copyright 2025 Irreducible Inc.

mod error;
pub mod pcs;

use std::marker::PhantomData;

use binius_field::{Field, PackedExtension, PackedField};
use binius_math::{
	FieldBuffer, FieldSlice,
	inner_product::inner_product_buffers,
	multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate},
	ntt::{NeighborsLastMultiThread, domain_context::GenericPreExpanded},
};
use binius_prover::{
	fri::{self, CommitOutput},
	hash::{ParallelDigest, parallel_compression::ParallelPseudoCompression},
	merkle_tree::prover::BinaryMerkleTreeProver,
};
use binius_spartan_frontend::constraint_system::{MulConstraint, Operand, WitnessIndex};
use binius_spartan_verifier::{Verifier, config::B128};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::{SerializeBytes, checked_arithmetics::checked_log_2, rayon::prelude::*};
use digest::{Digest, FixedOutputReset, Output, core_api::BlockSizeUser};
pub use error::*;

/// Struct for proving instances of a particular constraint system.
///
/// The [`Self::setup`] constructor pre-processes reusable structures for proving instances of the
/// given constraint system. Then [`Self::prove`] is called one or more times with individual
/// instances.
#[derive(Debug)]
pub struct Prover<P, ParallelMerkleCompress, ParallelMerkleHasher: ParallelDigest>
where
	ParallelMerkleCompress: ParallelPseudoCompression<Output<ParallelMerkleHasher::Digest>, 2>,
{
	verifier: Verifier<ParallelMerkleHasher::Digest, ParallelMerkleCompress::Compression>,
	ntt: NeighborsLastMultiThread<GenericPreExpanded<B128>>,
	merkle_prover: BinaryMerkleTreeProver<B128, ParallelMerkleHasher, ParallelMerkleCompress>,
	_p_marker: PhantomData<P>,
}

impl<P, MerkleHash, ParallelMerkleCompress, ParallelMerkleHasher>
	Prover<P, ParallelMerkleCompress, ParallelMerkleHasher>
where
	P: PackedField<Scalar = B128> + PackedExtension<B128>,
	MerkleHash: Digest + BlockSizeUser + FixedOutputReset,
	ParallelMerkleHasher: ParallelDigest<Digest = MerkleHash>,
	ParallelMerkleCompress: ParallelPseudoCompression<Output<MerkleHash>, 2>,
	Output<MerkleHash>: SerializeBytes,
{
	/// Constructs a prover corresponding to a constraint system verifier.
	///
	/// See [`Prover`] struct documentation for details.
	pub fn setup(
		verifier: Verifier<MerkleHash, ParallelMerkleCompress::Compression>,
		compression: ParallelMerkleCompress,
	) -> Result<Self, Error> {
		let subspace = verifier.fri_params().rs_code().subspace();
		let domain_context = GenericPreExpanded::generate_from_subspace(subspace);
		let log_num_shares = binius_utils::rayon::current_num_threads().ilog2() as usize;
		let ntt = NeighborsLastMultiThread::new(domain_context, log_num_shares);

		let merkle_prover = BinaryMerkleTreeProver::<_, ParallelMerkleHasher, _>::new(compression);

		Ok(Prover {
			verifier,
			ntt,
			merkle_prover,
			_p_marker: PhantomData,
		})
	}

	pub fn prove<Challenger_: Challenger>(
		&self,
		witness: &[B128],
		transcript: &mut ProverTranscript<Challenger_>,
	) -> Result<(), Error> {
		let _prove_guard =
			tracing::info_span!("Prove", operation = "prove", perfetto_category = "operation")
				.entered();

		let cs = self.verifier.constraint_system();

		// Check that the witness length matches the constraint system
		let expected_size = cs.size();
		if witness.len() != expected_size {
			return Err(Error::ArgumentError {
				arg: "witness".to_string(),
				msg: format!("witness has {} elements, expected {}", witness.len(), expected_size),
			});
		}

		let log_mul_constraints = checked_log_2(cs.mul_constraints().len());

		// Pack witness into field elements
		// TODO: Populate witness directly into a FieldBuffer
		let witness_packed = pack_witness::<P>(cs.log_size() as usize, witness);

		// Commit the witness
		let CommitOutput {
			commitment: trace_commitment,
			committed: codeword_committed,
			codeword,
		} = fri::commit_interleaved(
			self.verifier.fri_params(),
			&self.ntt,
			&self.merkle_prover,
			witness_packed.to_ref(),
		)?;
		transcript.message().write(&trace_commitment);

		let mulcheck_witness =
			build_mulcheck_witness(cs.mul_constraints(), witness_packed.to_ref());

		// Sample random evaluation point
		let r_x = transcript.sample_vec(log_mul_constraints);

		let r_x_tensor = eq_ind_partial_eval::<P>(&r_x);
		let a_eval = inner_product_buffers(&mulcheck_witness.a, &r_x_tensor);
		let b_eval = inner_product_buffers(&mulcheck_witness.b, &r_x_tensor);
		let c_eval = inner_product_buffers(&mulcheck_witness.c, &r_x_tensor);

		transcript.message().write(&a_eval);
		transcript.message().write(&b_eval);
		transcript.message().write(&c_eval);

		// Sample random evaluation point
		let r_y = transcript.sample_vec(self.verifier.constraint_system().log_size() as usize);

		// Compute the evaluation claim
		let evaluation_claim = evaluate(&witness_packed, &r_y)?;

		// Write the evaluation claim to the transcript
		transcript.message().write(&evaluation_claim);

		// Prove the evaluation
		let pcs_prover =
			pcs::PCSProver::new(&self.ntt, &self.merkle_prover, self.verifier.fri_params());
		pcs_prover.prove(
			&codeword,
			&codeword_committed,
			witness_packed,
			&r_y,
			evaluation_claim,
			transcript,
		)?;

		Ok(())
	}
}

fn pack_witness<P: PackedField<Scalar = B128>>(
	log_witness_elems: usize,
	witness: &[B128],
) -> FieldBuffer<P> {
	// Precondition: witness length must match expected size
	let expected_size = 1 << log_witness_elems;
	assert_eq!(
		witness.len(),
		expected_size,
		"witness length {} does not match expected size {}",
		witness.len(),
		expected_size
	);

	let len = 1 << log_witness_elems.saturating_sub(P::LOG_WIDTH);
	let mut packed_witness = Vec::<P>::with_capacity(len);

	packed_witness
		.spare_capacity_mut()
		.into_par_iter()
		.enumerate()
		.for_each(|(i, dst)| {
			let offset = i << P::LOG_WIDTH;
			let value = P::from_fn(|j| witness[offset + j]);

			dst.write(value);
		});

	// SAFETY: We just initialized all elements
	unsafe {
		packed_witness.set_len(len);
	};

	FieldBuffer::new(log_witness_elems, packed_witness.into_boxed_slice())
		.expect("FieldBuffer::new should succeed with correct log_witness_elems")
}

/// Witness data for multiplication constraint checking.
///
/// Contains the evaluated operands a, b, and c for all multiplication constraints,
/// packed into field buffers for efficient processing.
pub struct MulCheckWitness<P: PackedField> {
	pub a: FieldBuffer<P>,
	pub b: FieldBuffer<P>,
	pub c: FieldBuffer<P>,
}

/// Evaluates an operand by XORing witness values at the specified indices.
fn eval_operand<P: PackedField>(
	witness: &FieldSlice<P>,
	operand: &Operand<WitnessIndex>,
) -> P::Scalar
where
	P::Scalar: Field,
{
	operand
		.wires()
		.iter()
		.map(|idx| witness.get(idx.0 as usize))
		.sum()
}

/// Builds the witness for multiplication constraint checking.
///
/// Extracts and packs the a, b, and c operand values for each multiplication constraint.
/// This is analogous to `build_bitand_witness` in binius-prover but works with B128
/// field elements instead of word-level operations.
#[tracing::instrument(skip_all, level = "debug")]
fn build_mulcheck_witness<F: Field, P: PackedField<Scalar = F>>(
	mul_constraints: &[MulConstraint<WitnessIndex>],
	witness: FieldSlice<P>,
) -> MulCheckWitness<P> {
	fn get_a(c: &MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex> {
		&c.a
	}
	fn get_b(c: &MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex> {
		&c.b
	}
	fn get_c(c: &MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex> {
		&c.c
	}

	let n_constraints = mul_constraints.len();
	assert!(n_constraints > 0, "mul_constraints must not be empty");

	let log_n_constraints = checked_log_2(n_constraints);

	let len = 1 << log_n_constraints.saturating_sub(P::LOG_WIDTH);
	let mut a = Vec::<P>::with_capacity(len);
	let mut b = Vec::<P>::with_capacity(len);
	let mut c = Vec::<P>::with_capacity(len);

	(a.spare_capacity_mut(), b.spare_capacity_mut(), c.spare_capacity_mut())
		.into_par_iter()
		.enumerate()
		.for_each(|(i, (a_i, b_i, c_i))| {
			let offset = i << P::LOG_WIDTH;

			for (dst, get_operand) in [
				(a_i, get_a as fn(&MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex>),
				(b_i, get_b as fn(&MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex>),
				(c_i, get_c as fn(&MulConstraint<WitnessIndex>) -> &Operand<WitnessIndex>),
			] {
				let val = P::from_fn(|j| {
					let constraint_idx = offset + j;
					if constraint_idx < n_constraints {
						eval_operand(&witness, get_operand(&mul_constraints[constraint_idx]))
					} else {
						F::ZERO
					}
				});
				dst.write(val);
			}
		});

	// Safety: all entries in a, b, c are initialized in the parallel loop above.
	unsafe {
		a.set_len(len);
		b.set_len(len);
		c.set_len(len);
	}

	MulCheckWitness {
		a: FieldBuffer::new(log_n_constraints, a.into_boxed_slice())
			.expect("FieldBuffer::new should succeed with correct log_n_constraints"),
		b: FieldBuffer::new(log_n_constraints, b.into_boxed_slice())
			.expect("FieldBuffer::new should succeed with correct log_n_constraints"),
		c: FieldBuffer::new(log_n_constraints, c.into_boxed_slice())
			.expect("FieldBuffer::new should succeed with correct log_n_constraints"),
	}
}
