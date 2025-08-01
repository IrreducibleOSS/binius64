// Copyright 2025 Irreducible Inc.

use std::ops::Range;

use binius_field::{BinaryField, Field, PackedField};
use binius_frontend::word::Word;
use binius_math::{FieldBuffer, inner_product::inner_product_buffers};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::rayon::{current_num_threads, prelude::*};
use binius_verifier::{
	config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	protocols::{
		shift::{BITMUL_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT},
		sumcheck::{SumcheckOutput, common::RoundCoeffs},
	},
};
use itertools::{Itertools, izip};
use tracing::instrument;

use super::{
	error::Error,
	monster::build_h_triplet,
	prove::OperatorData,
	record::{Operation, ProverConstraintSystem},
	utils::make_field_buffer,
};
use crate::protocols::sumcheck::{
	bivariate_product::BivariateProductSumcheckProver, common::SumcheckProver,
};

const LOG_LEN: usize = LOG_WORD_SIZE_BITS + LOG_WORD_SIZE_BITS;

/// `MultilinearTriplet` holds three field buffers, corresponding to the
/// three shift variants.
/// Every field buffer implicitly has `log_len = 2 * LOG_WORD_SIZE_BITS`.
#[derive(Debug, Clone)]
pub struct MultilinearTriplet<P: PackedField> {
	pub sll: FieldBuffer<P>,
	pub srl: FieldBuffer<P>,
	pub sra: FieldBuffer<P>,
}

/// Proves the first phase of the shift reduction.
/// Computes the g and h multilinears and performs the sumcheck.
#[instrument(skip_all, name = "prover_phase_1")]
pub fn prove_phase_1<F: BinaryField, P: PackedField<Scalar = F>, C: Challenger>(
	record: &ProverConstraintSystem,
	words: &[Word],
	bitmul_data: &OperatorData<F>,
	intmul_data: &OperatorData<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	let [g_triplet_bitmul, g_triplet_intmul]: [MultilinearTriplet<P>; 2] =
		build_g_triplet(words, record, bitmul_data, intmul_data);

	let h_triplet_bitmul = build_h_triplet(bitmul_data.r_zhat_prime)?;
	let h_triplet_intmul = build_h_triplet(intmul_data.r_zhat_prime)?;

	run_phase_1_sumcheck(
		[g_triplet_bitmul, g_triplet_intmul],
		[h_triplet_bitmul, h_triplet_intmul],
		[bitmul_data.batched_eval(), intmul_data.batched_eval()],
		transcript,
	)
}

/// Runs the first phase sumcheck.
///
/// This sumcheck is setup to handle any number of operators
/// supported by the shift reduction.
/// For each operator, there is a pair of h and g `MultilinearTriplet`s.
/// The g triplet already incorporates batching randomness, so the claim
/// to be proven is on the sum of the bivariate products across each
/// pair of g and h multilinears.
#[instrument(skip_all, name = "run_sumcheck")]
fn run_phase_1_sumcheck<
	F: Field,
	P: PackedField<Scalar = F>,
	C: Challenger,
	const OPERATOR_COUNT: usize,
>(
	g_triplets: [MultilinearTriplet<P>; OPERATOR_COUNT],
	h_triplets: [MultilinearTriplet<P>; OPERATOR_COUNT],
	sums: [F; OPERATOR_COUNT],
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	// Build `BivariateProductSumcheckProver` provers.
	let mut provers = izip!(g_triplets, h_triplets, sums)
		.flat_map(|(g_triplet, h_triplet, sum)| {
			let sll_sum = inner_product_buffers(&g_triplet.sll, &h_triplet.sll);
			let slr_sum = inner_product_buffers(&g_triplet.srl, &h_triplet.srl);
			let sar_sum = sum - sll_sum - slr_sum;
			[
				(g_triplet.sll, h_triplet.sll, sll_sum),
				(g_triplet.srl, h_triplet.srl, slr_sum),
				(g_triplet.sra, h_triplet.sra, sar_sum),
			]
		})
		.map(|(left_buf, right_buf, sum)| {
			BivariateProductSumcheckProver::new([left_buf, right_buf], sum)
				.map_err(Error::from_sumcheck_new)
		})
		.collect::<Result<Vec<_>, _>>()?;

	// Perform the sumcheck rounds, collecting challenges.
	let n_vars = 2 * LOG_WORD_SIZE_BITS;
	let mut challenges = Vec::with_capacity(n_vars);
	for _ in 0..n_vars {
		let mut all_round_coeffs = Vec::new();
		for prover in &mut provers {
			all_round_coeffs.extend(prover.execute().map_err(Error::from_sumcheck_execute)?);
		}

		let summed_round_coeffs = all_round_coeffs
			.into_iter()
			.rfold(RoundCoeffs::default(), |acc, coeffs| acc + &coeffs);

		let round_proof = summed_round_coeffs.truncate();

		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		let challenge = transcript.sample();
		challenges.push(challenge);

		for prover in &mut provers {
			prover.fold(challenge).map_err(Error::from_sumcheck_fold)?;
		}
	}
	challenges.reverse();

	let multilinear_evals = provers
		.into_iter()
		.map(|prover| prover.finish().map_err(Error::from_sumcheck_finish))
		.collect::<Result<Vec<Vec<F>>, _>>()?;

	// Evaluate the composition polynomial to compute `gamma`.
	let gamma = multilinear_evals
		.into_iter()
		.map(|prover_evals| {
			assert_eq!(prover_evals.len(), 2);
			let h_eval = prover_evals[0];
			let g_eval = prover_evals[1];
			h_eval * g_eval
		})
		.sum();

	Ok(SumcheckOutput {
		challenges,
		eval: gamma,
	})
}

#[instrument(skip_all, name = "build_g_triplet")]
fn build_g_triplet<F: Field, P: PackedField<Scalar = F>>(
	words: &[Word],
	record: &ProverConstraintSystem,
	bitmul_operator_data: &OperatorData<F>,
	intmul_operator_data: &OperatorData<F>,
) -> [MultilinearTriplet<P>; 2] {
	let num_chunks = current_num_threads();
	let chunk_size = (words.len() as f64 / num_chunks as f64).ceil() as usize;

	const BITMUL_ACC_SIZE: usize = BITMUL_ARITY * SHIFT_VARIANT_COUNT * (1 << LOG_LEN);
	const INTMUL_ACC_SIZE: usize = INTMUL_ARITY * SHIFT_VARIANT_COUNT * (1 << LOG_LEN);

	let (bitmul_multilinears, intmul_multilinears) = words
		.into_par_iter()
		.zip(record.key_ranges.par_iter())
		.chunks(chunk_size)
		.map(|chunk| {
			let mut bitmul_multilinears = vec![F::ZERO; BITMUL_ACC_SIZE];
			let mut intmul_multilinears = vec![F::ZERO; INTMUL_ACC_SIZE];

			for (word, Range { start, end }) in chunk {
				let keys = &record.keys[*start as usize..*end as usize];

				for key in keys {
					let (tensor, multilinears) = match key.operation {
						Operation::BitwiseAnd => {
							(&bitmul_operator_data.r_x_prime_tensor, &mut bitmul_multilinears)
						}
						Operation::IntegerMul => {
							(&intmul_operator_data.r_x_prime_tensor, &mut intmul_multilinears)
						}
					};

					let acc = key.accumulate(&record.constraint_indices, tensor);

					let start = key.id as usize * WORD_SIZE_BITS;
					let end = start + WORD_SIZE_BITS;

					let mut word = *word;
					for val in multilinears[start..end].iter_mut() {
						if word & Word::ONE == Word::ONE {
							*val += acc;
						}
						word = word >> 1;
					}
				}
			}

			(bitmul_multilinears, intmul_multilinears)
		})
		.reduce(
			|| (vec![F::ZERO; BITMUL_ACC_SIZE], vec![F::ZERO; INTMUL_ACC_SIZE]),
			|(mut acc_bitmul, mut acc_intmul), (local_bitmul, local_intmul)| {
				izip!(acc_bitmul.iter_mut(), local_bitmul.iter()).for_each(|(acc, local)| {
					*acc += *local;
				});
				izip!(acc_intmul.iter_mut(), local_intmul.iter()).for_each(|(acc, local)| {
					*acc += *local;
				});
				(acc_bitmul, acc_intmul)
			},
		);

	let bitmul_triplet = build_multilinear_triplet_for_operator(
		&bitmul_multilinears,
		bitmul_operator_data,
		BITMUL_ARITY,
	);
	let intmul_triplet = build_multilinear_triplet_for_operator(
		&intmul_multilinears,
		intmul_operator_data,
		INTMUL_ARITY,
	);

	[bitmul_triplet, intmul_triplet]
}

#[instrument(skip_all, name = "build_multilinear_triplet_for_operator")]
fn build_multilinear_triplet_for_operator<F: Field, P: PackedField<Scalar = F>>(
	multilinears: &[F],
	operator_data: &OperatorData<F>,
	arity: usize,
) -> MultilinearTriplet<P> {
	let lambda_packed = P::broadcast(operator_data.lambda);
	let lambda_powers = (0..arity)
		.map(|i| lambda_packed.pow(1 + i as u64))
		.collect::<Vec<_>>();

	let (sll_buffers, srl_buffers, sra_buffers): (Vec<_>, Vec<_>, Vec<_>) = multilinears
		.chunks(SHIFT_VARIANT_COUNT * (1 << LOG_LEN))
		.take(arity)
		.map(|chunk| {
			let [sll_chunk, srl_chunk, sra_chunk] = chunk
				.chunks(1 << LOG_LEN)
				.collect::<Vec<_>>()
				.try_into()
				.expect("chunk has SHIFT_VARIANT_COUNT parts of size 1 << LOG_LEN");
			(
				make_field_buffer(sll_chunk.to_vec()),
				make_field_buffer(srl_chunk.to_vec()),
				make_field_buffer(sra_chunk.to_vec()),
			)
		})
		.multiunzip();

	let combine = |buffers: &[FieldBuffer<P>]| {
		izip!(lambda_powers.iter(), buffers).fold(
			FieldBuffer::zeros(LOG_LEN),
			|mut acc, (power, buffer)| {
				izip!(acc.as_mut(), buffer.as_ref()).for_each(|(res, buf)| *res += *power * *buf);
				acc
			},
		)
	};

	MultilinearTriplet {
		sll: combine(&sll_buffers),
		srl: combine(&srl_buffers),
		sra: combine(&sra_buffers),
	}
}
