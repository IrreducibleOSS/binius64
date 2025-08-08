// Copyright 2025 Irreducible Inc.

use std::{array, ops::Range};

use binius_core::word::Word;
use binius_field::{AESTowerField8b, BinaryField, Field, PackedField};
use binius_math::{FieldBuffer, inner_product::inner_product_buffers};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::rayon::prelude::*;
use binius_verifier::{
	config::{B1, LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	protocols::{
		shift::{BITAND_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT},
		sumcheck::{SumcheckOutput, common::RoundCoeffs},
	},
};
use itertools::izip;
use tracing::instrument;

use super::{
	error::Error,
	key_collection::{KeyCollection, Operation},
	monster::build_h_triplet,
	prove::PreparedOperatorData,
};
use crate::protocols::sumcheck::{
	bivariate_product::BivariateProductSumcheckProver, common::SumcheckProver,
};

/// `MultilinearTriplet` holds three field buffers, corresponding to the
/// three shift variants. Every field buffer implicitly has
/// `log_len = 2 * LOG_WORD_SIZE_BITS`.
#[derive(Debug, Clone)]
pub struct MultilinearTriplet<P: PackedField> {
	pub sll: FieldBuffer<P>,
	pub srl: FieldBuffer<P>,
	pub sra: FieldBuffer<P>,
}

// This is the number of variables in the g (and h) multilinears of phase 1.
const LOG_LEN: usize = LOG_WORD_SIZE_BITS + LOG_WORD_SIZE_BITS;

/// Constructs the "g" multilinear triplets for both BITAND and INTMUL operations.
/// Proves the first phase of the shift reduction.
/// Computes the g and h multilinears and performs the sumcheck.
#[instrument(skip_all, name = "prover_phase_1")]
pub fn prove_phase_1<F, P: PackedField<Scalar = F>, C: Challenger>(
	key_collection: &KeyCollection,
	words: &[Word],
	bitand_data: &PreparedOperatorData<F>,
	intmul_data: &PreparedOperatorData<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error>
where
	F: BinaryField + From<AESTowerField8b>,
{
	let [g_triplet_bitand, g_triplet_intmul]: [MultilinearTriplet<P>; 2] =
		build_g_triplet(words, key_collection, bitand_data, intmul_data)?;

	let h_triplet_bitand = build_h_triplet(bitand_data.r_zhat_prime)?;
	let h_triplet_intmul = build_h_triplet(intmul_data.r_zhat_prime)?;

	run_phase_1_sumcheck(
		[g_triplet_bitand, g_triplet_intmul],
		[h_triplet_bitand, h_triplet_intmul],
		[bitand_data.batched_eval(), intmul_data.batched_eval()],
		transcript,
	)
}

/// Runs the phase 1 sumcheck protocol for shift constraint verification.
///
/// Executes a sumcheck over bivariate products of g and h multilinear triplets for each
/// operation (BITAND, INTMUL). The protocol proves that the sum of g·h products across
/// all shift variants equals the claimed batched evaluation.
///
/// # Protocol Structure
///
/// For each operation, creates 3 bivariate product sumcheck provers (one per shift variant):
/// - g_sll · h_sll with claim `sll_sum`
/// - g_srl · h_srl with claim `srl_sum`
/// - g_sra · h_sra with claim `sar_sum = total_sum - sll_sum - srl_sum`
///
/// The g triplets incorporate batching randomness (lambda weighting), while h triplets
/// encode the shift operation behavior at the univariate challenge points.
///
/// # Parameters
///
/// - `g_triplets`: g multilinear triplets for each operation (witness-dependent)
/// - `h_triplets`: h multilinear triplets for each operation (challenge-dependent)
/// - `sums`: Expected total sums for each operation from lambda-weighted evaluation claims
///
/// # Returns
///
/// `SumcheckOutput` containing the challenge vector and final evaluation `gamma`
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
			let srl_sum = inner_product_buffers(&g_triplet.srl, &h_triplet.srl);
			let sra_sum = sum - sll_sum - srl_sum;
			[
				(g_triplet.sll, h_triplet.sll, sll_sum),
				(g_triplet.srl, h_triplet.srl, srl_sum),
				(g_triplet.sra, h_triplet.sra, sra_sum),
			]
		})
		.map(|(left_buf, right_buf, sum)| {
			BivariateProductSumcheckProver::new([left_buf, right_buf], sum)
		})
		.collect::<Result<Vec<_>, _>>()?;

	// Perform the sumcheck rounds, collecting challenges.
	let n_vars = 2 * LOG_WORD_SIZE_BITS;
	let mut challenges = Vec::with_capacity(n_vars);
	for _ in 0..n_vars {
		let mut all_round_coeffs = Vec::new();
		for prover in &mut provers {
			all_round_coeffs.extend(prover.execute()?);
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
			prover.fold(challenge)?;
		}
	}
	challenges.reverse();

	let multilinear_evals = provers
		.into_iter()
		.map(|prover| prover.finish())
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

/// Constructs the "g" multilinear triplets for both BITAND and INTMUL operations.
///
/// This function builds the g multilinear polynomials used in phase 1 of the shift protocol.
/// For each operation (BITAND and INTMUL), it constructs three multilinear polynomials
/// corresponding to the three shift variants (SLL, SRL, SRA).
///
/// # Construction Process
///
/// 1. **Parallel Processing**: Words are processed in parallel chunks for efficiency
/// 2. **Key Processing**: For each word, iterate through its associated keys from the key
///    collection
/// 3. **Accumulation**: For each key, accumulate its contribution weighted by the r_x' tensor
/// 4. **Word Expansion**: Expand each witness word bitwise to populate the g multilinears
/// 5. **Lambda Weighting**: Apply lambda powers to weight different operand positions
///
/// # Returns
///
/// An array `[bitand_triplet, intmul_triplet]` where each triplet contains the three
/// shift variant multilinears for that operation.
///
/// # Usage
///
/// Used in phase 1 to construct the constant size g multilinears
/// that will participate in the phase 1 sumcheck protocol.
#[instrument(skip_all, name = "build_g_triplet")]
fn build_g_triplet<F: BinaryField, P: PackedField<Scalar = F>>(
	words: &[Word],
	key_collection: &KeyCollection,
	bitand_operator_data: &PreparedOperatorData<F>,
	intmul_operator_data: &PreparedOperatorData<F>,
) -> Result<[MultilinearTriplet<P>; 2], Error> {
	const BITAND_ACC_SIZE: usize = BITAND_ARITY * SHIFT_VARIANT_COUNT * (1 << LOG_LEN);
	const INTMUL_ACC_SIZE: usize = INTMUL_ARITY * SHIFT_VARIANT_COUNT * (1 << LOG_LEN);

	let (bitand_multilinears, intmul_multilinears) = words
		.par_iter()
		.zip(key_collection.key_ranges.par_iter())
		.fold(
			|| {
				(
					vec![F::ZERO; BITAND_ACC_SIZE].into_boxed_slice(),
					vec![F::ZERO; INTMUL_ACC_SIZE].into_boxed_slice(),
				)
			},
			|(mut bitand_multilinears, mut intmul_multilinears), (word, Range { start, end })| {
				let keys = &key_collection.keys[*start as usize..*end as usize];

				for key in keys {
					let (tensor, multilinears) = match key.operation {
						Operation::BitwiseAnd => {
							(&bitand_operator_data.r_x_prime_tensor, &mut bitand_multilinears)
						}
						Operation::IntegerMul => {
							(&intmul_operator_data.r_x_prime_tensor, &mut intmul_multilinears)
						}
					};

					let acc = key.accumulate(&key_collection.constraint_indices, tensor.as_ref());

					let start = key.id as usize * WORD_SIZE_BITS;
					let end = start + WORD_SIZE_BITS;

					for (i, val) in multilinears[start..end].iter_mut().enumerate() {
						*val += acc * B1::from((word.0 >> i) & 1 == 1);
					}
				}

				(bitand_multilinears, intmul_multilinears)
			},
		)
		.reduce(
			|| {
				(
					vec![F::ZERO; BITAND_ACC_SIZE].into_boxed_slice(),
					vec![F::ZERO; INTMUL_ACC_SIZE].into_boxed_slice(),
				)
			},
			|(mut acc_bitand, mut acc_intmul), (local_bitand, local_intmul)| {
				izip!(acc_bitand.iter_mut(), local_bitand.iter()).for_each(|(acc, local)| {
					*acc += *local;
				});
				izip!(acc_intmul.iter_mut(), local_intmul.iter()).for_each(|(acc, local)| {
					*acc += *local;
				});
				(acc_bitand, acc_intmul)
			},
		);

	let bitand_triplet = build_multilinear_triplet_for_operator(
		&bitand_multilinears,
		bitand_operator_data,
		BITAND_ARITY,
	)?;
	let intmul_triplet = build_multilinear_triplet_for_operator(
		&intmul_multilinears,
		intmul_operator_data,
		INTMUL_ARITY,
	)?;

	Ok([bitand_triplet, intmul_triplet])
}

/// Builds a multilinear triplet for a single operation by combining its operand multilinears.
///
/// Takes the raw multilinears for all operands and shift variants of an operation,
/// applies lambda weighting to each operand, and combines them into a single triplet.
/// Each operand of index `i` gets weighted by λ^(i+1).
#[instrument(skip_all, name = "build_multilinear_triplet_for_operator")]
fn build_multilinear_triplet_for_operator<F: Field, P: PackedField<Scalar = F>>(
	multilinears: &[F],
	operator_data: &PreparedOperatorData<F>,
	arity: usize,
) -> Result<MultilinearTriplet<P>, Error> {
	let lambda_packed = P::broadcast(operator_data.lambda);
	let lambda_powers = (0..arity)
		.map(|i| lambda_packed.pow(1 + i as u64))
		.collect::<Vec<_>>();

	let [mut sll_buffers, mut srl_buffers, mut sra_buffers] =
		array::from_fn(|_| Vec::with_capacity(arity));

	for chunk in multilinears
		.chunks(SHIFT_VARIANT_COUNT * (1 << LOG_LEN))
		.take(arity)
	{
		let [sll_chunk, srl_chunk, sra_chunk] = chunk
			.chunks(1 << LOG_LEN)
			.collect::<Vec<_>>()
			.try_into()
			.expect("chunk has SHIFT_VARIANT_COUNT parts of size 1 << LOG_LEN");

		sll_buffers.push(FieldBuffer::from_values(sll_chunk)?);
		srl_buffers.push(FieldBuffer::from_values(srl_chunk)?);
		sra_buffers.push(FieldBuffer::from_values(sra_chunk)?);
	}

	let combine = |buffers: &[FieldBuffer<P>]| {
		izip!(lambda_powers.iter(), buffers).fold(
			FieldBuffer::zeros(LOG_LEN),
			|mut acc, (power, buffer)| {
				izip!(acc.as_mut(), buffer.as_ref()).for_each(|(res, buf)| *res += *power * *buf);
				acc
			},
		)
	};

	Ok(MultilinearTriplet {
		sll: combine(&sll_buffers),
		srl: combine(&srl_buffers),
		sra: combine(&sra_buffers),
	})
}
