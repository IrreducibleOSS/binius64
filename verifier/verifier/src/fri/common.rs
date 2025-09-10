// Copyright 2024-2025 Irreducible Inc.

use std::marker::PhantomData;

use binius_field::{BinaryField, ExtensionField};
use binius_math::{ntt::AdditiveNTT, reed_solomon::ReedSolomonCode};
use binius_utils::{bail, checked_arithmetics::log2_ceil_usize};
use getset::{CopyGetters, Getters};

use super::error::Error;
use crate::merkle_tree::MerkleTreeScheme;

/// Parameters for an FRI interleaved code proximity protocol.
#[derive(Debug, Clone, Getters, CopyGetters)]
pub struct FRIParams<F, FA>
where
	F: BinaryField,
	FA: BinaryField,
{
	/// The Reed-Solomon code the verifier is testing proximity to.
	#[getset(get = "pub")]
	rs_code: ReedSolomonCode<FA>,
	/// Vector commitment scheme for the codeword oracle.
	#[getset(get_copy = "pub")]
	log_batch_size: usize,
	/// The reduction arities between each oracle sent to the verifier.
	fold_arities: Vec<usize>,
	/// The number oracle consistency queries required during the query phase.
	#[getset(get_copy = "pub")]
	n_test_queries: usize,
	_marker: PhantomData<F>,
}

impl<F, FA> FRIParams<F, FA>
where
	F: BinaryField + ExtensionField<FA>,
	FA: BinaryField,
{
	pub fn new(
		rs_code: ReedSolomonCode<FA>,
		log_batch_size: usize,
		fold_arities: Vec<usize>,
		n_test_queries: usize,
	) -> Result<Self, Error> {
		if fold_arities.iter().sum::<usize>() >= rs_code.log_dim() + log_batch_size {
			bail!(Error::InvalidFoldAritySequence)
		}

		Ok(Self {
			rs_code,
			log_batch_size,
			fold_arities,
			n_test_queries,
			_marker: PhantomData,
		})
	}

	/// Choose commit parameters based on protocol parameters, using a constant fold arity.
	///
	/// ## Arguments
	///
	/// * `log_msg_len` - the binary logarithm of the length of the message to commit.
	/// * `security_bits` - the target security level in bits.
	/// * `log_inv_rate` - the binary logarithm of the inverse Reed–Solomon code rate.
	/// * `arity` - the folding arity.
	pub fn choose_with_constant_fold_arity(
		ntt: &impl AdditiveNTT<Field = FA>,
		log_msg_len: usize,
		security_bits: usize,
		log_inv_rate: usize,
		arity: usize,
	) -> Result<Self, Error> {
		assert!(arity > 0);

		let log_dim = log_msg_len.saturating_sub(arity);
		let log_batch_size = log_msg_len.min(arity);
		let rs_code = ReedSolomonCode::with_ntt_subspace(ntt, log_dim, log_inv_rate)?;
		let n_test_queries = calculate_n_test_queries::<F, _>(security_bits, &rs_code)?;

		let cap_height = log2_ceil_usize(n_test_queries);
		let fold_arities = std::iter::repeat_n(
			arity,
			log_msg_len.saturating_sub(cap_height.saturating_sub(log_inv_rate)) / arity,
		)
		.collect::<Vec<_>>();
		// here is the down-to-earth explanation of what we're doing: we want the terminal
		// codeword's log-length to be at least as large as the Merkle cap height. note that
		// `total_vars + log_inv_rate - sum(fold_arities)` is exactly the log-length of the
		// terminal codeword; we want this number to be ≥ cap height. so fold_arities will repeat
		// `arity` the maximal number of times possible, while maintaining that `total_vars +
		// log_inv_rate - sum(fold_arities) ≥ cap_height` stays true. this arity-selection
		// strategy can be characterized as: "terminate as late as you can, while maintaining that
		// no Merkle cap is strictly smaller than `cap_height`." this strategy does attain that
		// property: the Merkle path height of the last non-terminal codeword will equal the
		// log-length of the terminal codeword, which is ≥ cap height by fiat. moreover, if we
		// terminated later than we are above, then this would stop being true. imagine what would
		// happen if we took the above terminal codeword and continued folding. in that case, we
		// would Merklize this word, again with the coset-bundling trick; the post-bundling path
		// height would thus be `total_vars + log_inv_rate - sum(fold_arities) - arity`. but we
		// already agreed (by the maximality of the number of times we subtracted `arity`) that
		// the above number will be < cap_height. in other words, its Merkle cap will be
		// short. equivalently: this is the latest termination for which the `min` in
		// `optimal_verify_layer` will never trigger; i.e., we will have log2_ceil_usize(n_queries)
		// ≤ tree_depth there. it can be shown that this strategy beats any strategy which
		// terminates later than it does (in other words, by doing this, we are NOT terminating
		// TOO early!). this doesn't mean that we shouldn't terminate EVEN earlier (maybe we
		// should). but this approach is conservative and simple; and it's easy to show that you
		// won't lose by doing this.

		// see https://github.com/IrreducibleOSS/binius/pull/300 for proof of this fact

		// how should we handle the case `fold_arities = []`, i.e. total_vars + log_inv_rate -
		// cap_height < arity? in that case, we would lose nothing by making the entire thing
		// interleaved, i.e., setting `log_batch_size := total_vars`, so `terminal_codeword` lives
		// in the interleaving of the repetition code (and so is itself a repetition codeword!).
		// encoding is trivial. but there's a circularity: whether `total_vars + log_inv_rate -
		// cap_height < arity` or not depends on `cap_height`, which depends on `n_test_queries`,
		// which depends on `log_dim`--- soundness depends on block length!---which finally itself
		// depends on whether we're using the repetition code or not. of course this circular
		// dependency is artificial, since in the case `log_batch_size = total_vars` and `log_dim
		// = 0`, we're sending the entire message anyway, so the FRI portion is essentially
		// trivial / superfluous, and the security is perfect. and in any case we could evade it
		// simply by calculating `n_test_queries` and `cap_height` using the provisional `log_dim
		// := total_vars.saturating_sub(arity)`, proceeding as above, and only then, if we find
		// out post facto that `fold_arities = []`, overwriting `log_batch_size := total_vars` and
		// `log_dim = 0`---and even recalculating `n_test_queries` if we wanted (though of course
		// it doesn't matter---we could do 0 queries in that case, and we would still get
		// security---and in fact during the actual querying part we will skip querying
		// anyway). in any case, from a purely code-simplicity point of view, the simplest approach
		// is to bite the bullet and let `log_batch_size := min(total_vars, arity)` for good---and
		// keep it there, even if we post-facto find out that `fold_arities = []`. the cost of
		// this is that the prover has to do a nontrivial (though small!) interleaved encoding, as
		// opposed to a trivial one.
		Self::new(rs_code, log_batch_size, fold_arities, n_test_queries)
	}

	pub fn n_fold_rounds(&self) -> usize {
		self.log_msg_len()
	}

	/// Number of oracles sent during the fold rounds.
	pub fn n_oracles(&self) -> usize {
		self.fold_arities.len()
	}

	/// Number of bits in the query indices sampled during the query phase.
	pub fn index_bits(&self) -> usize {
		self.fold_arities
			.first()
			.map(|arity| self.log_len() - arity)
			// If there is no folding, there are no random queries either
			.unwrap_or(0)
	}

	/// Number of folding challenges the verifier sends after receiving the last oracle.
	pub fn n_final_challenges(&self) -> usize {
		self.n_fold_rounds() - self.fold_arities.iter().sum::<usize>()
	}

	/// The reduction arities between each oracle sent to the verifier.
	pub fn fold_arities(&self) -> &[usize] {
		&self.fold_arities
	}

	/// The binary logarithm of the length of the initial oracle.
	pub fn log_len(&self) -> usize {
		self.rs_code.log_len() + self.log_batch_size()
	}

	/// The binary logarithm of the length of the initial message.
	pub fn log_msg_len(&self) -> usize {
		self.rs_code.log_dim() + self.log_batch_size()
	}
}

/// This layer allows minimizing the proof size.
pub fn vcs_optimal_layers_depths_iter<'a, F, FA, VCS>(
	fri_params: &'a FRIParams<F, FA>,
	vcs: &'a VCS,
) -> impl Iterator<Item = usize> + 'a
where
	VCS: MerkleTreeScheme<F>,
	F: BinaryField + ExtensionField<FA>,
	FA: BinaryField,
{
	fri_params
		.fold_arities()
		.iter()
		.scan(fri_params.log_len(), |log_n_cosets, arity| {
			*log_n_cosets -= arity;
			Some(vcs.optimal_verify_layer(fri_params.n_test_queries(), *log_n_cosets))
		})
}

/// Calculates the number of test queries required to achieve a target security level.
///
/// Throws [`Error::ParameterError`] if the security level is unattainable given the code
/// parameters.
pub fn calculate_n_test_queries<F, FEncode>(
	security_bits: usize,
	code: &ReedSolomonCode<FEncode>,
) -> Result<usize, Error>
where
	F: BinaryField + ExtensionField<FEncode>,
	FEncode: BinaryField,
{
	let field_size = 2.0_f64.powi(F::N_BITS as i32);
	let sumcheck_err = (2 * code.log_dim()) as f64 / field_size;
	// 2 ⋅ ℓ' / |T_{τ}|
	let folding_err = code.len() as f64 / field_size;
	// 2^{ℓ' + R} / |T_{τ}|
	let per_query_err = 0.5 * (1f64 + 2.0f64.powi(-(code.log_inv_rate() as i32)));
	let allowed_query_err = 2.0_f64.powi(-(security_bits as i32)) - sumcheck_err - folding_err;
	if allowed_query_err <= 0.0 {
		return Err(Error::ParameterError);
	}
	let n_queries = allowed_query_err.log(per_query_err).ceil() as usize;
	Ok(n_queries)
}

/// Heuristic for estimating the optimal FRI folding arity that minimizes proof size.
///
/// `log_block_length` is the binary logarithm of the  block length of the Reed–Solomon code.
pub fn estimate_optimal_arity(
	log_block_length: usize,
	digest_size: usize,
	field_size: usize,
) -> usize {
	(1..=log_block_length)
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
		.unwrap_or(1)
}

#[cfg(test)]
mod tests {
	use assert_matches::assert_matches;

	use super::*;
	use crate::config::B128;

	#[test]
	fn test_calculate_n_test_queries() {
		let security_bits = 96;
		let rs_code = ReedSolomonCode::new(28, 1).unwrap();
		let n_test_queries =
			calculate_n_test_queries::<B128, B128>(security_bits, &rs_code).unwrap();
		assert_eq!(n_test_queries, 232);

		let rs_code = ReedSolomonCode::new(28, 2).unwrap();
		let n_test_queries =
			calculate_n_test_queries::<B128, B128>(security_bits, &rs_code).unwrap();
		assert_eq!(n_test_queries, 143);
	}

	#[test]
	fn test_calculate_n_test_queries_unsatisfiable() {
		let security_bits = 128;
		let rs_code = ReedSolomonCode::<B128>::new(28, 1).unwrap();
		assert_matches!(
			calculate_n_test_queries::<B128, _>(security_bits, &rs_code),
			Err(Error::ParameterError)
		);
	}

	#[test]
	fn test_estimate_optimal_arity() {
		let field_size = 128;
		for log_block_length in 22..35 {
			let digest_size = 256;
			assert_eq!(estimate_optimal_arity(log_block_length, digest_size, field_size), 4);
		}

		for log_block_length in 22..28 {
			let digest_size = 1024;
			assert_eq!(estimate_optimal_arity(log_block_length, digest_size, field_size), 6);
		}
	}
}
