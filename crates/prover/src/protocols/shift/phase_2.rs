// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField, Field, PackedField};
use binius_frontend::word::Word;
use binius_math::{FieldBuffer, inner_product::inner_product_buffers};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::{
	shift::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS, tensor_expand as tensor_expand_scalar},
	sumcheck::{SumcheckOutput, common::BatchSumcheckOutput},
};
use either::Either;
use itertools::izip;
use tracing::instrument;

use super::{
	error::Error, monster::compute_monster_multilinear_for_operator, prove::OperatorData,
	utils::make_field_buffer,
};
use crate::protocols::{
	InOutCheckProver,
	sumcheck::{
		batch::batch_prove, bivariate_product::BivariateProductSumcheckProver,
		common::SumcheckProver,
	},
};

/// Compute the partially folded witness by applying
/// multilinear variable `r_j` across the bits of each witness word.
#[instrument(skip_all, name = "compute_folded_witness")]
fn compute_folded_witness<F: Field, P: PackedField<Scalar = F>>(
	words: &[Word],
	r_j: &[F],
) -> FieldBuffer<P> {
	let expanded_r_j = tensor_expand_scalar(r_j, LOG_WORD_SIZE_BITS);

	let folded_witness = words
		.iter()
		.map(|word| {
			(0..WORD_SIZE_BITS)
				.filter(|&i| (*word >> (i as u32)) & Word::ONE == Word::ONE)
				.map(|i| expanded_r_j[i])
				.sum()
		})
		.collect::<Vec<F>>();

	make_field_buffer(folded_witness)
}

/// Proves the second phase of the shift reduction.
/// TODO: document
#[instrument(skip_all, name = "prove_phase_2")]
pub fn prove_phase_2<F: BinaryField, P: PackedField<Scalar = F>, C: Challenger>(
	_inout_n_vars: usize,
	words: &[Word],
	bitmul_data: &OperatorData<3, F>,
	intmul_data: &OperatorData<4, F>,
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

	let r_j_witness = compute_folded_witness::<_, P>(words, &r_j);

	#[cfg(debug_assertions)]
	let cloned_r_j_witness_for_debugging = r_j_witness.clone();

	let bitmul_monster_multilinear =
		compute_monster_multilinear_for_operator::<3, _, P>(words.len(), bitmul_data, &r_j, &r_s)?;

	let intmul_monster_multilinear =
		compute_monster_multilinear_for_operator::<4, _, P>(words.len(), intmul_data, &r_j, &r_s)?;

	let mut monster_multilinear = FieldBuffer::zeros(bitmul_monster_multilinear.log_len());

	izip!(
		monster_multilinear.as_mut(),
		bitmul_monster_multilinear.as_ref(),
		intmul_monster_multilinear.as_ref()
	)
	.for_each(|(dest, bitmul, intmul)| {
		*dest = *bitmul + *intmul;
	});

	assert_eq!(r_j_witness.len(), monster_multilinear.len());

	debug_assert_eq!(inner_product_buffers(&r_j_witness, &monster_multilinear), gamma);

	let mut shift_prover =
		BivariateProductSumcheckProver::new([r_j_witness.clone(), monster_multilinear], gamma)
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
	let n_vars = r_j_witness.log_len();
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
		let expected_witness_eval =
			inner_product_buffers(&cloned_r_j_witness_for_debugging, &r_y_tensor);
		debug_assert_eq!(witness_eval, expected_witness_eval);
	}

	Ok(SumcheckOutput {
		challenges: [r_j, r_y].concat(),
		eval: witness_eval,
	})
}
