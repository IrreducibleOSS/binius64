// Copyright 2025 Irreducible Inc.
use std::{
	cmp::{max, min},
	marker::PhantomData,
};

use binius_field::BinaryField;
use binius_math::{BinarySubspace, ReedSolomonCode};
use binius_utils::checked_arithmetics::log2_ceil_usize;
use digest::{Output, OutputSizeUser};

/// Parameters for FRI.
///
/// Generics:
/// - `F`: The field over which the protocol is executed.
/// - `H`, `C`: Choice of hashing and compression function for the merkle trees.
#[derive(Debug, Clone)]
pub struct FRIParams<F, H, C> {
	/// The hashing algorithm used for hashing leaves in the merkle trees.
	digest: PhantomData<H>,
	/// The compression algorithm used for compressing nodes in the merkle trees.
	compression: C,
	/// The layer used for committing in the merkle trees.
	commit_layer: usize,
	/// Information about the folding rounds in FRI.
	round_types: Vec<RoundType>,
	/// The code used for encoding the message at the beginning of FRI.
	rs_code: ReedSolomonCode<F>,
	/// The number of queries in the QUERY phase.
	num_queries: usize,
}

/// Information about one folding round in FRI.
#[derive(Debug, Clone)]
pub enum RoundType {
	InitialCommitment {
		log_len: usize,
		log_batch_size: usize,
	},
	Vacant,
	Commitment {
		log_len: usize,
		log_batch_size: usize,
	},
	TerminalCodeword {
		log_len: usize,
	},
}

impl<F, H: OutputSizeUser, C> FRIParams<F, H, C>
where
	F: BinaryField,
{
	/// Create FRI parameters.
	///
	/// Arguments:
	/// - `compression`: The compression function used in the merkle trees.
	/// - `commit_layer`: The layer of commitment in the merkle trees.
	/// - `poly_log_len`: Base-2 logarithm of the length of the multilinear polynomial that will be
	///   committed.
	/// - `rs_code`: The code for used for encoding the message at the beginning of FRI. \ Must
	///   satisfy `rs_code.log_dim() + fold_arities[0] >= poly_log_len`.
	/// - `fold_arities`: The arities for folding. Each arity must be at least 1, and there must be
	///   at least one folding arity.
	/// - `num_queries`: The number of queries in the QUERY phase.
	///
	/// ## Preconditions
	///
	/// - `fold_arities` must contain at least one arity
	/// - each arity in `fold_arities` must be strictly bigger than 0
	/// - the sum of the fold arities must be at most `poly_log_len`
	/// - `rs_code.log_dim() + fold_arities[0] >= poly_log_len`
	pub fn new(
		compression: C,
		commit_layer: usize,
		poly_log_len: usize,
		rs_code: ReedSolomonCode<F>,
		fold_arities: Vec<usize>,
		num_queries: usize,
	) -> Self {
		assert!(!fold_arities.is_empty());
		assert!(rs_code.log_dim() + fold_arities[0] >= poly_log_len);

		// we count the initial commitment as a "round", hence the "+1"
		let num_rounds = poly_log_len + 1;
		let mut round_types = vec![RoundType::Vacant; num_rounds];

		// round 0 is the commitment of the initial codeword
		let mut log_len = poly_log_len + rs_code.log_inv_rate();
		round_types[0] = RoundType::InitialCommitment {
			log_len,
			log_batch_size: fold_arities[0],
		};

		// determine the other round types depending on the fold arities
		let mut index = 0;
		let mut fold_arities_iter = fold_arities.iter().peekable();
		while let Some(&fold_arity) = fold_arities_iter.next() {
			assert!(fold_arity > 0);
			index += fold_arity;
			assert!(fold_arity <= log_len);
			log_len -= fold_arity;
			round_types[index] = match fold_arities_iter.peek() {
				Some(&&next_fold_arity) => {
					// there is another folding round to come, so we do a commitment
					RoundType::Commitment {
						log_len,
						log_batch_size: next_fold_arity,
					}
				}
				None => {
					assert!(log_len >= rs_code.log_inv_rate());
					// this is the terminal folding round, where we reveal the full codeword
					RoundType::TerminalCodeword { log_len }
				}
			}
		}

		Self {
			digest: PhantomData,
			compression,
			commit_layer,
			rs_code,
			num_queries,
			round_types,
		}
	}

	/// Heuristic for estimating the optimal FRI folding arity that minimizes proof size.
	///
	/// Arguments:
	/// - `poly_log_len`: Base-2 logarithm of the length of the multilinear polynomial that will be
	///   committed.
	/// - `log_inv_rate`: Base-2 logarithm of the inverse of the rate that will be used.
	pub fn estimate_optimal_arity(poly_log_len: usize, log_inv_rate: usize) -> usize {
		// NOTE: This is copied over from the old FRI implementation.
		let log_block_length = poly_log_len + log_inv_rate;
		let digest_size = size_of::<Output<H>>();
		let field_size = size_of::<F>();
		let fold_arity = (1..=log_block_length)
			.map(|arity| {
				(
					// for given arity, return a tuple (arity, estimate of query_proof_size).
					// this estimate is basd on the following approximation of a single
					// query_proof_size, where $\vartheta$ is the arity: $\big((n-\vartheta) +
					// (n-2\vartheta) + \ldots\big)\text{digest_size} +
					// \frac{n-\vartheta}{\vartheta}2^{\vartheta}\text{field_size}.$
					arity,
					((log_block_length) / 2 * digest_size + (1 << arity) * field_size)
						* (log_block_length - arity)
						/ arity,
				)
			})
			// now scan and terminate the iterator when query_proof_size increases.
			.scan(None, |old: &mut Option<(usize, usize)>, new| {
				let should_continue = !matches!(*old, Some(ref old) if new.1 > old.1);
				*old = Some(new);
				should_continue.then_some(new)
			})
			.last()
			.map(|(arity, _)| arity)
			.unwrap_or(1);

		min(fold_arity, poly_log_len)
	}

	/// Create FRI parameters with constant fold arity and automatically computed number of queries.
	///
	/// Arguments:
	/// - `compression`: Compression algorithm used in merkle tree.
	/// - `poly_log_len`: Base-2 logarithm of the length of the multilinear polynomial that will be
	///   committed.
	/// - `log_inv_rate`: Base-2 logarithm of the inverse of the rate that will be used.
	/// - `subspace`: The subspace used for encoding the first interleaved codeword.
	/// - `fold_arity`: The constant folding arity.
	/// - `security_bits`: Determines required level of security, which determines the number of
	///   queries.
	///
	/// ## Preconditions
	///
	/// - `0 < fold_arity`
	/// - `fold_arity <= poly_log_len`
	/// - (in particular this implies `0 < poly_log_len`)
	/// - `subspace.dim() == poly_log_len + log_inv_rate - fold_arity`
	pub fn new_with_constant_arity(
		compression: C,
		poly_log_len: usize,
		log_inv_rate: usize,
		subspace: BinarySubspace<F>,
		fold_arity: usize,
		security_bits: usize,
	) -> Self {
		assert!(0 < fold_arity);
		assert!(fold_arity <= poly_log_len);
		assert_eq!(subspace.dim(), poly_log_len + log_inv_rate - fold_arity);

		// pick RS code accordingly
		let rs_code =
			ReedSolomonCode::with_subspace(subspace, poly_log_len - fold_arity, log_inv_rate)
				.unwrap();

		// compute number of queries according to required security
		// NOTE: This is copied over from the old FRI implementation.
		let field_size = 2.0_f64.powi(F::N_BITS as i32);
		let sumcheck_err = (2 * rs_code.log_dim()) as f64 / field_size;
		// 2 ⋅ ℓ' / |T_{τ}|
		let folding_err = rs_code.len() as f64 / field_size;
		// 2^{ℓ' + R} / |T_{τ}|
		let per_query_err = 0.5 * (1f64 + 2.0f64.powi(-(rs_code.log_inv_rate() as i32)));
		let allowed_query_err = 2.0_f64.powi(-(security_bits as i32)) - sumcheck_err - folding_err;
		assert!(allowed_query_err > 0.0);
		let num_queries = allowed_query_err.log(per_query_err).ceil() as usize;

		// choose commit layer of the merkle trees according to how many openings they need to do
		let commit_layer = log2_ceil_usize(num_queries);

		// fill fold_arities
		// NOTE: This is copied over from the old FRI implementation.
		let num_fold_commitments =
			poly_log_len.saturating_sub(commit_layer.saturating_sub(log_inv_rate)) / fold_arity;
		let num_fold_commitments = max(num_fold_commitments, 1);
		let fold_arities = vec![fold_arity; num_fold_commitments];

		assert!(fold_arities[0] < poly_log_len);

		Self::new(compression, commit_layer, poly_log_len, rs_code, fold_arities, num_queries)
	}

	pub fn compression(&self) -> &C {
		&self.compression
	}

	pub fn rs_code(&self) -> &ReedSolomonCode<F> {
		&self.rs_code
	}

	/// counts the initial commitment as an additional round
	pub fn num_rounds(&self) -> usize {
		self.round_types.len()
	}

	pub fn log_msg_len(&self) -> usize {
		self.round_types.len() - 1
	}

	pub fn round_type(&self, i: usize) -> &RoundType {
		&self.round_types[i]
	}

	pub fn commit_layer(&self) -> usize {
		self.commit_layer
	}

	pub fn num_queries(&self) -> usize {
		self.num_queries
	}
}

#[cfg(test)]
mod tests {
	use binius_math::BinarySubspace;

	use super::*;
	use crate::hash::{StdCompression, StdDigest};

	type F = crate::config::B128;
	type H = StdDigest;
	type C = StdCompression;

	#[test]
	fn test_estimate_optimal_arity() {
		for poly_log_len in 22..35 {
			let arity = FRIParams::<F, H, C>::estimate_optimal_arity(poly_log_len, 0);
			assert_eq!(arity, 4);
		}
	}

	#[test]
	fn test_num_queries() {
		{
			let poly_log_len = 32;
			let log_inv_rate = 1;
			let fold_arity =
				FRIParams::<F, H, C>::estimate_optimal_arity(poly_log_len, log_inv_rate);
			let subspace =
				BinarySubspace::with_dim(poly_log_len + log_inv_rate - fold_arity).unwrap();
			let security_bits = 96;
			let fri_params = FRIParams::<F, H, C>::new_with_constant_arity(
				C::default(),
				poly_log_len,
				log_inv_rate,
				subspace,
				fold_arity,
				security_bits,
			);

			assert_eq!(fri_params.num_queries(), 232);
		}

		{
			let poly_log_len = 32;
			let log_inv_rate = 2;
			let fold_arity =
				FRIParams::<F, H, C>::estimate_optimal_arity(poly_log_len, log_inv_rate);
			let subspace =
				BinarySubspace::with_dim(poly_log_len + log_inv_rate - fold_arity).unwrap();
			let security_bits = 96;
			let fri_params = FRIParams::<F, H, C>::new_with_constant_arity(
				C::default(),
				poly_log_len,
				log_inv_rate,
				subspace,
				fold_arity,
				security_bits,
			);

			assert_eq!(fri_params.num_queries(), 143);
		}
	}
}
