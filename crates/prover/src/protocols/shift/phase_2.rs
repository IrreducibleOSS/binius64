// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, Field, PackedField};
use binius_frontend::word::Word;
use binius_math::FieldBuffer;
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::{config::LOG_WORD_SIZE_BITS, protocols::sumcheck::SumcheckOutput};
use tracing::instrument;

use super::{
	error::Error, monster::build_monster_multilinear, prove::OperatorData,
	record::ProverConstraintSystem, utils::tensor_expand_scalar,
};
use crate::{
	fold_word::fold_words,
	protocols::sumcheck::{
		bivariate_product::BivariateProductSumcheckProver, common::SumcheckProver,
	},
};

/// Proves the second phase of the shift reduction.
/// TODO: document
#[instrument(skip_all, name = "prove_phase_2")]
pub fn prove_phase_2<F: BinaryField, P: PackedField<Scalar = F>, C: Challenger>(
	record: &ProverConstraintSystem,
	_inout_n_vars: usize,
	words: &[Word],
	bitmul_data: &OperatorData<F>,
	intmul_data: &OperatorData<F>,
	phase_1_output: SumcheckOutput<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	let SumcheckOutput {
		challenges: mut r_jr_s,
		eval: gamma,
	} = phase_1_output;
	// Split challenges as r_j,r_s where r_j is the first LOG_WORD_SIZE_BITS
	// variables and r_s is the last LOG_WORD_SIZE_BITS variables
	// Thus r_s are the more significant variables.
	let r_s = r_jr_s.split_off(LOG_WORD_SIZE_BITS);
	let r_j = r_jr_s;

	let r_j_tensor = tensor_expand_scalar(&r_j, LOG_WORD_SIZE_BITS);
	let r_j_witness = fold_words::<_, P>(words, &r_j_tensor);

	let monster_multilinear =
		build_monster_multilinear(record, bitmul_data, intmul_data, &r_j, &r_s)?;

	run_sumcheck(r_j_witness, monster_multilinear, r_j, gamma, transcript)
}

#[instrument(skip_all, name = "run_sumcheck")]
fn run_sumcheck<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	r_j_witness: FieldBuffer<P>,
	monster_multilinear: FieldBuffer<P>,
	r_j: Vec<F>,
	gamma: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	let n_vars = r_j_witness.log_len();

	#[cfg(debug_assertions)]
	let cloned_r_j_witness_for_debugging = r_j_witness.clone();

	let mut shift_prover =
		BivariateProductSumcheckProver::new([r_j_witness, monster_multilinear], gamma)
			.map_err(Error::from_sumcheck_new)?;

	// // TODO: incorporate inout prover
	// // let inout_buf = FieldBuffer::new(
	// // 	inout_n_vars,
	// // 	r_j_witness
	// // 		.as_ref()
	// // 		.iter()
	// // 		.take(1 << inout_n_vars.saturating_sub(P::LOG_WIDTH))
	// // 		.copied()
	// // 		.collect(),
	// // )?;
	// // let inout_eval_point = transcript.sample_vec(inout_n_vars);
	// // let inout_prover = InOutCheckProver::new(r_j_witness, inout_buf,
	// &inout_eval_point)?;

	// let provers = vec![Either::Left(shift_prover), Either::Right(inout_prover)];
	// let BatchSumcheckOutput {
	// 	challenges: r_y,
	// 	mut multilinear_evals,
	// } = batch_prove(provers, transcript)?;

	// TODO: Replace this with batch prove
	let mut r_y = Vec::with_capacity(n_vars);
	for _ in 0..n_vars {
		let mut round_coeffs = shift_prover
			.execute()
			.map_err(Error::from_sumcheck_execute)?;
		assert_eq!(round_coeffs.len(), 1);
		let round_coeffs = round_coeffs.pop().unwrap();

		let round_proof = round_coeffs.truncate();

		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		let challenge = transcript.sample();
		r_y.push(challenge);

		shift_prover
			.fold(challenge)
			.map_err(Error::from_sumcheck_fold)?;
	}
	r_y.reverse();

	let mut evals = shift_prover.finish().map_err(Error::from_sumcheck_finish)?;
	assert_eq!(evals.len(), 2);

	let mut writer = transcript.message();
	writer.write_scalar_slice(&evals);

	let _monster_eval = evals.pop().expect("there are 2 multilnears");
	let witness_eval = evals.pop().expect("there is 1 remaining eval");

	#[cfg(debug_assertions)]
	{
		let r_y_tensor = binius_math::multilinear::eq::eq_ind_partial_eval(&r_y);
		let expected_witness_eval = binius_math::inner_product::inner_product_buffers(
			&cloned_r_j_witness_for_debugging,
			&r_y_tensor,
		);
		debug_assert_eq!(witness_eval, expected_witness_eval);
	}

	Ok(SumcheckOutput {
		challenges: [r_j, r_y].concat(),
		eval: witness_eval,
	})
}
