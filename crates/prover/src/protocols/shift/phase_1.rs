// Copyright 2025 Irreducible Inc.

use std::{array, ops::Range};

use binius_core::word::Word;
use binius_field::{Field, PackedField};
use binius_math::FieldBuffer;
use binius_utils::rayon::prelude::*;
use binius_verifier::{
	config::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS},
	protocols::shift::{BITAND_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT},
};
use itertools::izip;
use tracing::instrument;

use super::{
	error::Error,
	key_collection::{KeyCollection, Operation},
	prove::OperatorData,
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
#[allow(dead_code)] // TODO: With phase 2 integration, dead code warnings will disappear.
#[instrument(skip_all, name = "build_g_triplet")]
fn build_g_triplet<F: Field, P: PackedField<Scalar = F>>(
	words: &[Word],
	key_collection: &KeyCollection,
	bitand_operator_data: &OperatorData<F>,
	intmul_operator_data: &OperatorData<F>,
) -> Result<[MultilinearTriplet<P>; 2], Error> {
	const BITAND_ACC_SIZE: usize = BITAND_ARITY * SHIFT_VARIANT_COUNT * (1 << LOG_LEN);
	const INTMUL_ACC_SIZE: usize = INTMUL_ARITY * SHIFT_VARIANT_COUNT * (1 << LOG_LEN);

	let (bitand_multilinears, intmul_multilinears) = words
		.into_par_iter()
		.zip(key_collection.key_ranges.par_iter())
		.map(|(word, Range { start, end })| {
			let mut bitand_multilinears = vec![F::ZERO; BITAND_ACC_SIZE];
			let mut intmul_multilinears = vec![F::ZERO; INTMUL_ACC_SIZE];

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

				let mut word = *word;
				for val in multilinears[start..end].iter_mut() {
					if word & Word::ONE == Word::ONE {
						*val += acc;
					}
					word = word >> 1;
				}
			}

			(bitand_multilinears, intmul_multilinears)
		})
		.reduce(
			|| (vec![F::ZERO; BITAND_ACC_SIZE], vec![F::ZERO; INTMUL_ACC_SIZE]),
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
	operator_data: &OperatorData<F>,
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
