// Copyright 2025 Irreducible Inc.

use binius_core::word::Word;
use binius_field::{AESTowerField8b, BinaryField, Field, PackedField};
use binius_math::{FieldBuffer, multilinear::eq::eq_ind_partial_eval};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::{config::LOG_WORD_SIZE_BITS, protocols::sumcheck::SumcheckOutput};
use either::Either;
use tracing::instrument;

use super::{
	error::Error, key_collection::KeyCollection, monster::build_monster_multilinear,
	prove::PreparedOperatorData,
};
use crate::{
	fold_word::fold_words,
	protocols::{
		inout_check::InOutCheckProver,
		sumcheck::{
			MleToSumCheckDecorator,
			batch::{BatchSumcheckOutput, batch_prove},
			bivariate_product::BivariateProductSumcheckProver,
		},
	},
};

/// Proves the second phase of the shift protocol reduction.
///
/// This function implements phase 2 of the shift protocol prover, which takes the output
/// from phase 1 and completes the shift reduction by proving the relationship between
/// the witness and the monster multilinear polynomial.
///
/// # Protocol Steps
/// 1. **Challenge Splitting**: Splits phase 1 challenges into `r_j` and `r_s` components
/// 2. **Witness Folding**: Folds the witness words using the `r_j` challenges
/// 3. **Monster Multilinear Construction**: Builds the monster multilinear from key collection and
///    operator data
/// 4. **Sumcheck Execution**: Runs bivariate product sumcheck to prove witness ×
///    monster_multilinear relationship
///
/// # Parameters
/// - `key_collection`: Prover's key collection representing the constraint system
/// - `words`: The witness words
/// - `bitand_data`: Operator data for bit multiplication constraints
/// - `intmul_data`: Operator data for integer multiplication constraints
/// - `phase_1_output`: Challenges and evaluation from the first phase
/// - `transcript`: The prover's transcript
///
/// # Returns
/// Returns `SumcheckOutput` containing the combined challenges `[r_j, r_y]` and witness evaluation,
/// or an error if the protocol fails.
#[allow(clippy::too_many_arguments)]
#[instrument(skip_all, name = "prove_phase_2")]
pub fn prove_phase_2<F, P: PackedField<Scalar = F>, C: Challenger>(
	inout_n_vars: usize,
	key_collection: &KeyCollection,
	words: &[Word],
	bitand_data: &PreparedOperatorData<F>,
	intmul_data: &PreparedOperatorData<F>,
	zeros_data: &PreparedOperatorData<F>,
	phase_1_output: SumcheckOutput<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error>
where
	F: BinaryField + From<AESTowerField8b>,
{
	let SumcheckOutput {
		challenges: mut r_jr_s,
		eval: gamma,
	} = phase_1_output;
	// Split challenges as r_j,r_s where r_j is the first LOG_WORD_SIZE_BITS
	// variables and r_s is the last LOG_WORD_SIZE_BITS variables
	// Thus r_s are the more significant variables.
	let r_s = r_jr_s.split_off(LOG_WORD_SIZE_BITS);
	let r_j = r_jr_s;

	let r_j_tensor = eq_ind_partial_eval::<F>(&r_j);
	let r_j_witness = fold_words::<_, P>(words, r_j_tensor.as_ref());

	let monster_multilinear = build_monster_multilinear(
		key_collection,
		bitand_data,
		intmul_data,
		zeros_data,
		&r_j,
		&r_s,
	)?;

	run_sumcheck(inout_n_vars, r_j_witness, monster_multilinear, r_j, gamma, transcript)
}

/// Executes the bivariate product sumcheck for the witness and monster multilinear relationship.
///
/// This helper function runs the actual sumcheck protocol to prove that the claimed
/// evaluation `gamma` equals the sum over all boolean assignments of the product
/// `witness(x) * monster_multilinear(x)`.
///
/// # Protocol Details
/// - Uses `BivariateProductSumcheckProver` to handle the product relationship
/// - Runs batch sumcheck to get new challenges `r_y` and multilinear evaluations
/// - Extracts witness evaluation and monster multilinear evaluation from the results
/// - In debug mode, verifies the witness evaluation against expected value
///
/// # Parameters
/// - `r_j_witness`: The witness folded at challenges `r_j`
/// - `monster_multilinear`: The monster multilinear polynomial constructed from constraints
/// - `r_j`: Challenge vector from phase 1 (first `LOG_WORD_SIZE_BITS` challenges)
/// - `gamma`: The claimed evaluation from phase 1
/// - `transcript`: The prover's transcript
///
/// # Returns
/// Returns `SumcheckOutput` with concatenated challenges `[r_j, r_y]` and witness evaluation.
#[instrument(skip_all, name = "run_sumcheck")]
fn run_sumcheck<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	inout_n_vars: usize,
	r_j_witness: FieldBuffer<P>,
	monster_multilinear: FieldBuffer<P>,
	r_j: Vec<F>,
	gamma: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<SumcheckOutput<F>, Error> {
	#[cfg(debug_assertions)]
	let cloned_r_j_witness_for_debugging = r_j_witness.clone();

	let shift_prover =
		BivariateProductSumcheckProver::new([r_j_witness.clone(), monster_multilinear], gamma)?;

	let inout_buf = FieldBuffer::new(
		inout_n_vars,
		r_j_witness
			.as_ref()
			.iter()
			.take(1 << inout_n_vars.saturating_sub(P::LOG_WIDTH))
			.copied()
			.collect(),
	)?;
	let inout_eval_point = transcript.sample_vec(inout_n_vars);
	let inout_mle_prover = InOutCheckProver::new(r_j_witness, inout_buf, &inout_eval_point)?;
	let inout_prover = MleToSumCheckDecorator::new(inout_mle_prover);

	let provers = vec![Either::Left(shift_prover), Either::Right(inout_prover)];

	let BatchSumcheckOutput {
		challenges: r_y,
		mut multilinear_evals,
	} = batch_prove(provers, transcript)?;

	assert_eq!(multilinear_evals.len(), 2);

	let mut inout_evals = multilinear_evals.pop().expect("there are 2 provers");
	let mut shift_evals = multilinear_evals.pop().expect("there are 2 provers");

	assert_eq!(inout_evals.len(), 1);
	let _inout_witness_eval = inout_evals.pop().expect("there is 1 eval");

	assert_eq!(shift_evals.len(), 2);
	let _monster_eval = shift_evals.pop().expect("there are 2 multilinears");
	let witness_eval = shift_evals.pop().expect("there is 1 remaining eval");

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
