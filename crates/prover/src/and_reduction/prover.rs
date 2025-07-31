use binius_field::{BinaryField, Field, PackedBinaryField128x1b, PackedExtension, PackedField};
use binius_math::{BinarySubspace, multilinear::eq::eq_ind_partial_eval};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::{
	and_reduction::{
		univariate::univariate_poly::{GenericPo2UnivariatePoly, UnivariatePolyIsomorphic},
		utils::constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
	},
	config::B1,
};

use super::{
	fold_lookup::FoldLookup, sumcheck_round_messages, univariate::ntt_lookup::NTTLookup,
	utils::multivariate::OneBitOblongMultilinear,
};
use crate::protocols::sumcheck::{
	Error, ProveSingleOutput, prove_single_mlecheck, quadratic_mle::QuadraticMleCheckProver,
};

/// Prover for the AND constraint reduction protocol via oblong univariate zerocheck.
///
/// See [`binius_verifier::and_reduction::verifier`] for the protocol specification.
pub struct OblongZerocheckProver<FChallenge, PNTTDomain>
where
	FChallenge: Field + From<PNTTDomain::Scalar> + BinaryField,
	PNTTDomain: PackedField,
{
	first_col: OneBitOblongMultilinear,
	second_col: OneBitOblongMultilinear,
	third_col: OneBitOblongMultilinear,
	big_field_zerocheck_challenges: Vec<FChallenge>,
	small_field_zerocheck_challenges: Vec<PNTTDomain::Scalar>,
	univariate_round_message: [FChallenge; ROWS_PER_HYPERCUBE_VERTEX],
	univariate_round_message_domain: BinarySubspace<FChallenge>,
}

/// Output from the AND reduction proving protocol.
///
/// Contains the results after completing both phases of the AND reduction protocol:
/// the univariate polynomial verification and the multilinear sumcheck reduction.
pub struct ProveAndReductionOutput<F: Field> {
	/// The output from the multilinear sumcheck protocol, containing:
	/// - The final evaluation claim
	/// - The challenges used in each round
	/// - The multilinear evaluations at the query point
	pub sumcheck_output: ProveSingleOutput<F>,
	/// The challenge value z sampled for Z after the univariate polynomial phase.
	/// This challenge is used to fold the oblong multilinears before the sumcheck phase.
	pub univariate_sumcheck_challenge: F,
}

impl<FChallenge, PNTTDomain> OblongZerocheckProver<FChallenge, PNTTDomain>
where
	FChallenge: Field + From<<PNTTDomain as PackedField>::Scalar> + BinaryField,
	PNTTDomain: PackedField + PackedExtension<B1, PackedSubfield = PackedBinaryField128x1b>,
	u8: From<<PNTTDomain as PackedField>::Scalar>,
	<PNTTDomain as PackedField>::Scalar: From<u8> + BinaryField,
{
	/// Creates a new oblong zerocheck prover for AND constraint reduction.
	///
	/// This constructor sets up the prover by precomputing the univariate polynomial evaluations
	/// that will be sent in the first round. The polynomial encodes the AND constraint verification
	/// across all values in the oblong dimension.
	///
	/// # Arguments
	///
	/// * `first_col` - The oblong multilinear polynomial A in the AND constraint A & B ^ C = 0
	/// * `second_col` - The oblong multilinear polynomial B in the AND constraint
	/// * `third_col` - The oblong multilinear polynomial C in the AND constraint
	/// * `big_field_zerocheck_challenges` - Challenges Z_{k+1},...,Zₙ in the large field FChallenge
	/// * `ntt_lookup` - Precomputed NTT lookup table for efficient polynomial evaluation
	/// * `small_field_zerocheck_challenges` - Challenges Z₁,...,Zₖ in the small field (at most 3
	///   challenges since we use an 8-bit subfield and require F₂-linear independence of all subset
	///   products)
	/// * `univariate_round_message_domain` - The domain for evaluating the univariate polynomial
	///
	/// # Implementation Details
	///
	/// The constructor:
	/// 1. Computes the equality indicator polynomial from the big field challenges
	/// 2. Uses the NTT lookup to efficiently compute the univariate polynomial evaluations
	/// 3. Caches these evaluations for later use in the execute() method
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		first_col: OneBitOblongMultilinear,
		second_col: OneBitOblongMultilinear,
		third_col: OneBitOblongMultilinear,
		big_field_zerocheck_challenges: Vec<FChallenge>,
		ntt_lookup: &NTTLookup<PNTTDomain>,
		small_field_zerocheck_challenges: Vec<PNTTDomain::Scalar>,
		univariate_round_message_domain: BinarySubspace<FChallenge>,
	) -> Self {
		let eq_ind_big_field_challenges = eq_ind_partial_eval(&big_field_zerocheck_challenges);

		let univariate_round_message =
			sumcheck_round_messages::univariate_round_message_extension_domain(
				&first_col,
				&second_col,
				&third_col,
				&eq_ind_big_field_challenges,
				ntt_lookup,
				&small_field_zerocheck_challenges,
			);

		Self {
			first_col,
			second_col,
			third_col,
			small_field_zerocheck_challenges,
			univariate_round_message,
			big_field_zerocheck_challenges,
			univariate_round_message_domain,
		}
	}

	/// Executes the first phase of the AND reduction protocol by computing the univariate
	/// polynomial.
	///
	/// This method computes the univariate polynomial R₀(Z) that encodes the AND constraint
	/// verification. The polynomial is evaluated on the extension domain (upper half) and these
	/// evaluations are sent to the verifier as the first round message.
	///
	/// # Returns
	///
	/// Returns a reference to the precomputed univariate polynomial evaluations on the extension
	/// domain. These are exactly `ROWS_PER_HYPERCUBE_VERTEX` field elements that represent
	/// R₀(Z) for Z in the upper half of the univariate domain.
	///
	/// # Note
	///
	/// The polynomial evaluations are precomputed in the constructor using the NTT lookup table
	/// for efficiency. This method simply returns the cached result.
	pub fn execute(&self) -> &[FChallenge; ROWS_PER_HYPERCUBE_VERTEX] {
		&self.univariate_round_message
	}

	/// Folds the oblong multilinears at the univariate challenge and creates the sumcheck prover.
	///
	/// This method performs the transition between Phase 1 (univariate polynomial) and Phase 2
	/// (multilinear sumcheck) of the AND reduction protocol. It folds the oblong multilinear
	/// polynomials by fixing X₀ to the challenge value, effectively reducing them to standard
	/// multilinear polynomials over the remaining variables.
	///
	/// # Arguments
	///
	/// * `round_message_domain` - The domain for the univariate polynomial (same as used in
	///   execute)
	/// * `challenge` - The random challenge z for Z received from the verifier
	///
	/// # Returns
	///
	/// Returns an `QuadraticMleCheckProver` configured to prove the sumcheck claim:
	/// R₀(z) = ∑_{X₀,...,Xₙ₋₁ ∈ {0,1}} (A(z,X₀,...,Xₙ₋₁)·B(z,X₀,...,Xₙ₋₁) -
	/// C(z,X₀,...,Xₙ₋₁))·eq(X₀,...,Xₙ₋₁; r₀,...,rₙ₋₁)
	///
	/// # Process
	///
	/// 1. Creates a fold lookup table for efficiently folding at the challenge point
	/// 2. Folds each of the three oblong multilinears (A, B, C) at Z = challenge
	/// 3. Combines the zerocheck challenges (small field + big field)
	/// 4. Evaluates the univariate polynomial at the challenge to get the sumcheck claim
	/// 5. Constructs the AND reduction sumcheck prover with the folded multilinears
	pub fn fold_and_send_reduced_prover(
		self,
		round_message_domain: BinarySubspace<FChallenge>,
		challenge: FChallenge,
	) -> QuadraticMleCheckProver<
		FChallenge,
		impl Fn([FChallenge; 3]) -> FChallenge,
		impl Fn([FChallenge; 3]) -> FChallenge,
		3,
	> {
		let univariate_domain = round_message_domain
			.reduce_dim(round_message_domain.dim() - 1)
			.expect("message domain should have dim>=1");
		let lookup = FoldLookup::<_, SKIPPED_VARS>::new(&univariate_domain, challenge);

		let proving_polys = [
			self.first_col.fold(&lookup),
			self.second_col.fold(&lookup),
			self.third_col.fold(&lookup),
		];

		let upcasted_small_field_challenges: Vec<_> = self
			.small_field_zerocheck_challenges
			.into_iter()
			.map(|i| FChallenge::from(i))
			.collect();

		let verifier_field_zerocheck_challenges: Vec<_> = upcasted_small_field_challenges
			.iter()
			.chain(self.big_field_zerocheck_challenges.iter())
			.copied()
			.collect();

		let mut first_round_message_coeffs = vec![FChallenge::ZERO; 2 * ROWS_PER_HYPERCUBE_VERTEX];

		first_round_message_coeffs[ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX]
			.copy_from_slice(&self.univariate_round_message);

		let first_round_message =
			GenericPo2UnivariatePoly::new(first_round_message_coeffs, round_message_domain);

		QuadraticMleCheckProver::new(
			proving_polys,
			|[a, b, c]| a * b - c,
			|[a, b, _]| a * b,
			&verifier_field_zerocheck_challenges,
			first_round_message.evaluate_at_challenge(challenge),
		)
		.expect("multilinears should have consistent dimensions")
	}

	/// Executes the complete AND reduction protocol with a Fiat-Shamir transcript.
	///
	/// This method orchestrates the entire AND reduction protocol:
	/// 1. Sends the univariate polynomial evaluations to the transcript
	/// 2. Receives the univariate challenge via Fiat-Shamir
	/// 3. Folds the oblong multilinears at the challenge point
	/// 4. Runs the multilinear sumcheck protocol
	///
	/// # Arguments
	///
	/// * `transcript` - The prover's transcript for non-interactive proof generation
	///
	/// # Returns
	///
	/// Returns `ProveAndReductionOutput` containing:
	/// - The sumcheck output with evaluation claims and challenges
	/// - The univariate challenge used for folding
	///
	/// # Errors
	///
	/// Returns an error if the sumcheck protocol fails
	///
	/// # Protocol Flow
	///
	/// 1. **Phase 1**: Write univariate polynomial evaluations to transcript
	/// 2. **Challenge**: Sample univariate challenge z via Fiat-Shamir
	/// 3. **Transition**: Fold oblong multilinears at Z = z
	/// 4. **Phase 2**: Execute sumcheck protocol on folded multilinears
	pub fn prove_with_transcript<TranscriptChallenger>(
		self,
		transcript: &mut ProverTranscript<TranscriptChallenger>,
	) -> Result<ProveAndReductionOutput<FChallenge>, Error>
	where
		TranscriptChallenger: Challenger,
	{
		let univariate_message_coeffs = self.execute().iter();

		for coeff in univariate_message_coeffs {
			transcript.message().write_scalar(*coeff);
		}

		let univariate_sumcheck_challenge = transcript.sample();
		let univariate_round_message_domain = self.univariate_round_message_domain.clone();
		let sumcheck_prover = self.fold_and_send_reduced_prover(
			univariate_round_message_domain,
			univariate_sumcheck_challenge,
		);

		Ok(ProveAndReductionOutput {
			sumcheck_output: prove_single_mlecheck(sumcheck_prover, transcript)?,
			univariate_sumcheck_challenge,
		})
	}
}

#[cfg(test)]
mod test {
	use std::{iter, iter::repeat_with};

	use binius_field::{AESTowerField8b, PackedAESBinaryField16x8b};
	use binius_frontend::word::Word;
	use binius_math::{BinarySubspace, multilinear::evaluate::evaluate};
	use binius_transcript::{ProverTranscript, fiat_shamir::CanSample};
	use binius_verifier::{
		and_reduction::{utils::constants::SKIPPED_VARS, verifier::verify_with_transcript},
		config::{B128, StdChallenger},
	};
	use itertools::Itertools;
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::OblongZerocheckProver;
	use crate::and_reduction::{
		fold_lookup::FoldLookup, prover_setup::ntt_lookup_from_prover_message_domain,
		utils::multivariate::OneBitOblongMultilinear,
	};

	fn random_one_bit_multivariate(
		log_num_rows: usize,
		mut rng: impl Rng,
	) -> OneBitOblongMultilinear {
		OneBitOblongMultilinear {
			log_num_rows,
			packed_evals: repeat_with(|| Word(rng.random()))
				.take(1 << (log_num_rows - SKIPPED_VARS))
				.collect(),
		}
	}

	#[test]
	fn test_transcript_prover_verifies() {
		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		let log_num_rows = 10;
		let mut rng = StdRng::seed_from_u64(0);

		let small_field_zerocheck_challenges = [
			AESTowerField8b::new(2),
			AESTowerField8b::new(4),
			AESTowerField8b::new(16),
		];
		let first_mlv = random_one_bit_multivariate(log_num_rows, &mut rng);
		let second_mlv = random_one_bit_multivariate(log_num_rows, &mut rng);
		let third_mlv = OneBitOblongMultilinear {
			log_num_rows,
			packed_evals: iter::zip(&first_mlv.packed_evals, &second_mlv.packed_evals)
				.map(|(&a, &b)| a & b)
				.collect(),
		};
		// Agreed-upon proof parameter

		let prover_message_domain = BinarySubspace::with_dim(SKIPPED_VARS + 1).unwrap();
		let verifier_message_domain = prover_message_domain.isomorphic();

		let ntt_lookup = ntt_lookup_from_prover_message_domain::<PackedAESBinaryField16x8b>(
			prover_message_domain,
		);

		// Prover is instantiated
		let big_field_zerocheck_challenges =
			prover_challenger.sample_vec(log_num_rows - SKIPPED_VARS - 3);
		let prover = OblongZerocheckProver::new(
			first_mlv.clone(),
			second_mlv.clone(),
			third_mlv.clone(),
			big_field_zerocheck_challenges.to_vec(),
			&ntt_lookup,
			small_field_zerocheck_challenges.to_vec(),
			verifier_message_domain.clone(),
		);

		let prove_output = prover
			.prove_with_transcript(&mut prover_challenger)
			.unwrap();

		let l2h_query_for_evaluation_point = prove_output
			.sumcheck_output
			.challenges
			.clone()
			.into_iter()
			.rev()
			.collect_vec();

		prover_challenger
			.message()
			.write_slice(&prove_output.sumcheck_output.multilinear_evals);

		let mut verifier_challenger = prover_challenger.into_verifier();

		let big_field_zerocheck_challenges =
			verifier_challenger.sample_vec(log_num_rows - SKIPPED_VARS - 3);

		let mut all_zerocheck_challenges = vec![];

		for small_field_challenge in small_field_zerocheck_challenges {
			all_zerocheck_challenges.push(B128::from(small_field_challenge));
		}

		for big_field_challenge in &big_field_zerocheck_challenges {
			all_zerocheck_challenges.push(*big_field_challenge);
		}

		let output = verify_with_transcript(
			&all_zerocheck_challenges,
			&mut verifier_challenger,
			verifier_message_domain.clone(),
		)
		.unwrap();

		let verifier_mle_eval_claims = verifier_challenger
			.message()
			.read_scalar_slice::<B128>(3)
			.unwrap();

		let verifier_univariate_domain = verifier_message_domain
			.reduce_dim(SKIPPED_VARS)
			.expect("reducing by 2 to a positive basis size");

		let one_bit_mlvs = [first_mlv, second_mlv, third_mlv];

		let verifier_transparent_fold_lookup =
			FoldLookup::new(&verifier_univariate_domain, output.univariate_sumcheck_challenge);
		for (i, eval) in verifier_mle_eval_claims.iter().enumerate().take(3) {
			assert_eq!(
				evaluate(
					&one_bit_mlvs[i].fold(&verifier_transparent_fold_lookup),
					&l2h_query_for_evaluation_point
				)
				.unwrap(),
				*eval
			);
		}

		assert_eq!(
			output.sumcheck_output.eval,
			verifier_mle_eval_claims[0] * verifier_mle_eval_claims[1] - verifier_mle_eval_claims[2]
		);

		// Sanity checks, but not necessary verifier assertions
		assert_eq!(output.sumcheck_output.challenges, prove_output.sumcheck_output.challenges);
		assert_eq!(
			output.univariate_sumcheck_challenge,
			prove_output.univariate_sumcheck_challenge
		);
	}
}
