// Copyright 2025 Irreducible Inc.

use std::array;

use binius_field::{BinaryField, Field, PackedField};
use binius_frontend::word::Word;
use binius_math::{FieldBuffer, inner_product::inner_product_buffers};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::{
	shift::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	sumcheck::{SumcheckOutput, common::RoundCoeffs},
};
use itertools::{izip, multiunzip};
use tracing::instrument;

use super::{
	error::Error, monster::compute_h_triplet_for_operator, prove::OperatorData,
	record::ShiftedValueKey, utils::make_field_buffer,
};
use crate::protocols::sumcheck::{
	bivariate_product::BivariateProductSumcheckProver, common::SumcheckProver,
};

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
#[instrument(skip_all, name = "phase_1")]
pub fn prove_phase_1<F: BinaryField, P: PackedField<Scalar = F>, C: Challenger>(
	words: &[Word],
	bitmul_data: &mut OperatorData<3, F>,
	intmul_data: &mut OperatorData<4, F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	let g_triplet_bitmul = compute_g_triplet_for_operator::<_, P, 3>(words, bitmul_data);
	let g_triplet_intmul = compute_g_triplet_for_operator::<_, P, 4>(words, intmul_data);

	let h_triplet_bitmul = compute_h_triplet_for_operator(bitmul_data.r_zhat_prime)?;
	let h_triplet_intmul = compute_h_triplet_for_operator(intmul_data.r_zhat_prime)?;

	run_phase_1_sumcheck(
		[g_triplet_bitmul, g_triplet_intmul],
		[h_triplet_bitmul, h_triplet_intmul],
		[bitmul_data.batched_eval(), intmul_data.batched_eval()],
		transcript,
	)
}

/// Runs the first phase sumcheck.
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

/// Computes a g multilinear triplet for an operator.
/// For shift variant `op`, the `op` field of the triplet is
/// the `2 * LOG_WORD_SIZE_BITS`-variate multilinear in
/// multilinear variables `j` and `s`:
/// $$
/// \sum_{m_idx, m in enumerate(operands)} \lambda^{1+m_idx} * g_{m, op}(j, s)
/// $$
#[instrument(skip_all, name = "compute_g_triplet_for_operator")]
fn compute_g_triplet_for_operator<F: Field, P: PackedField<Scalar = F>, const ARITY: usize>(
	words: &[Word],
	operator_data: &mut OperatorData<ARITY, F>,
) -> MultilinearTriplet<P> {
	// The log length of the multilinears in the triplet.
	const LOG_LEN: usize = LOG_WORD_SIZE_BITS + LOG_WORD_SIZE_BITS;

	// Build a triplet for each operand using the corresponding record.
	let triplets: [MultilinearTriplet<P>; ARITY] = operator_data
		.records
		.each_mut()
		.map(|record| build_triplet_from_record(words, record, &operator_data.r_x_prime_tensor));

	// Unzip the triplets into vectors of buffers (each of length `ARITY`), one for each shift
	// variant.
	let (sll_buffers, srl_buffers, sra_buffers): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(
		triplets
			.into_iter()
			.map(|MultilinearTriplet { sll, srl, sra }| (sll, srl, sra)),
	);

	// For each shift variant, we will combine the `ARITY` buffers into one using univariate
	// batching with lambda. The lambda batching begins with power 1, not 0, that way
	// making this batching soundly independent of batching for other operators.
	let lambda_packed = P::broadcast(operator_data.lambda);
	let lambda_powers: [P; ARITY] = array::from_fn(|i| lambda_packed.pow(1 + i as u64));

	let combine = |buffers: &[FieldBuffer<P>]| -> FieldBuffer<P> {
		// Note: Wrongly suspected this commented block would be faster.
		// let mut result = FieldBuffer::zeros(LOG_LEN);
		// for (k, val) in result.as_mut().iter_mut().enumerate() {
		// 	for (buffer, &lambda_power) in izip!(buffers.iter(), lambda_powers.iter()) {
		// 		*val += lambda_power * buffer.as_ref()[k];
		// 	}
		// }
		// result

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

/// Builds a g multilinear triplet for an operand of an operator
/// given the operand's record.
/// This function is the bottleneck of the prover's work
/// over the entire shift reduction.
#[instrument(skip_all, name = "build_triplet_from_record")]
fn build_triplet_from_record<F: Field, P: PackedField<Scalar = F>>(
	words: &[Word],
	record: &mut [Vec<ShiftedValueKey<F>>],
	tensor: &[F],
) -> MultilinearTriplet<P> {
	assert_eq!(record.len(), words.len());

	// Allocate the three multilinears, one for each shift variant.
	let mut multilinears = core::array::from_fn(|_| vec![F::ZERO; WORD_SIZE_BITS * WORD_SIZE_BITS]);

	// Note: Other loop ordering in original Python seems slower.
	// for (word, keys) in izip!(words, record) {
	// 	let mut word = word.0;
	// 	for i in 0..WORD_SIZE_BITS {
	// 		if word & 1 == 1 {
	// 			for key in keys {
	// 				let variant_index = key.shift_variant as usize;
	// 				let start_index = key.amount * WORD_SIZE_BITS;
	// 				let acc = key.accumulate(tensor);

	// 				multilinears[variant_index][start_index + i] += acc;
	// 			}
	// 		}
	// 		word >>= 1;
	// 	}
	// }

	// Every word is processed independently.
	for (word, keys) in izip!(words, record) {
		// Iteration across the keys is hot, but hot as hot as the inner
		// loop across the word bits.
		// Records could be setup to more efficiently identify the
		// `multilinear` and the `idx` in this hot loop, but the real
		// bottneck seems to be the inner most loop which is unavoidable.
		// The original Python model swapped the order of the loops,
		// and performed for me about 2.5 times slower for the RSA example.
		for key in keys {
			let multilinear = &mut multilinears[key.op as usize];

			let acc = key.accumulate(tensor);
			// Uncomment to try memoization
			// key.memo = acc;

			let mut idx = key.s * WORD_SIZE_BITS;

			let mut word = *word;

			for _ in 0..WORD_SIZE_BITS {
				if word & Word::ONE == Word::ONE {
					multilinear[idx] += acc;
				}
				word = word >> 1;
				idx += 1;
			}
		}
	}

	let [sll, srl, sra] = multilinears.map(make_field_buffer);

	MultilinearTriplet { sll, srl, sra }
}
