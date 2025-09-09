use std::marker::PhantomData;

use binius_field::BinaryField;
use binius_math::{ReedSolomonCode, ntt::DomainContext};

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
	// TODO remove?
	fold_arities: Vec<usize>,
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

impl<F, H, C> FRIParams<F, H, C>
where
	F: BinaryField,
{
	/// Create FRI parameters.
	///
	/// Arguments:
	/// - `compression`: The compression function used in the merkle trees.
	/// - `commit_layer`: The layer of commitment in the merkle trees.
	/// - `poly_log_len`: Base-2 logarithm of the length of the multilinear polynomial that will be committed.
	/// - `rs_code`: The code for used for encoding the message at the beginning of FRI. \
	///   Must satisfy `rs_code.log_dim() + fold_arities[0] >= poly_log_len`.
	/// - `fold_arities`: The arities for folding. Each arity must be at least 1, and there must be at least one folding arity.
	/// - `num_queries`: The number of queries in the QUERY phase.
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
		let num_rounds = rs_code.log_dim() + fold_arities[0] + 1;
		let mut round_types = vec![RoundType::Vacant; num_rounds];

		// round 0 is the commitment of the initial codeword
		round_types[0] = RoundType::InitialCommitment {
			log_len: rs_code.log_len() + fold_arities[0],
			log_batch_size: fold_arities[0],
		};

		// determine the other round types depending on the fold arities
		let mut index = 0;
		let mut log_len = rs_code.log_len() + fold_arities[0];
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
			fold_arities,
			num_queries,
			round_types,
		}
	}

	pub fn new_with_good_choices(
		compression: C,
		poly_log_len: usize,
		domain_context: &impl DomainContext<Field = F>,
	) -> Self {
		// FIXME TODO make calculation for good choices
		let commit_layer = 0;
		let num_queries = 100;
		let fold_arities = vec![1; poly_log_len];
		let log_inv_rate = 1;
		assert!(fold_arities[0] < poly_log_len);
		let rs_code = ReedSolomonCode::with_domain_context_subspace(
			domain_context,
			poly_log_len - fold_arities[0],
			log_inv_rate,
		)
		.unwrap();

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
