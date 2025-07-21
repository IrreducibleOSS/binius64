use binius_field::{AESTowerField8b, Field};
use binius_math::{multilinear::eq::eq_ind_partial_eval};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use itertools::Itertools;
use crate::protocols::sumcheck::{
	and_reduction::{
		fold_lookups::precompute_fold_lookup,
		one_bit_multivariate::OneBitMultivariate,
		sumcheck_prover::{AndReductionMultilinearSumcheckProver, FoldDirection},
		sumcheck_round_message::univariate_round_message,
		univariate::{
			delta::delta_poly,
			ntt_lookup::{NTTLookup, SKIPPED_VARS},
			subfield_isomorphism::SubfieldIsomorphismLookup,
			univariate_poly::{GenericPo2UnivariatePoly, UnivariatePoly},
		},
	},
	common::SumcheckProver,
};

pub struct OblongZerocheckProver<'a, FChallenge>
where
	FChallenge: Field,
{
	first_col: OneBitMultivariate,
	second_col: OneBitMultivariate,
	third_col: OneBitMultivariate,
	univariate_zerocheck_challenge: FChallenge,
	multilinear_big_field_zerocheck_challenges: Vec<FChallenge>,
	small_field_zerocheck_challenges: Vec<AESTowerField8b>,
	subfield_iso_lookup: &'a SubfieldIsomorphismLookup<FChallenge>,
	univariate_round_message: GenericPo2UnivariatePoly<'a, FChallenge, FChallenge>,
}

impl<'a, FChallenge> OblongZerocheckProver<'a, FChallenge>
where
	FChallenge: Field,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		first_col: OneBitMultivariate,
		second_col: OneBitMultivariate,
		third_col: OneBitMultivariate,
		multilinear_big_field_zerocheck_challenges: Vec<FChallenge>,
		ntt_lookup: NTTLookup,
		small_field_zerocheck_challenges: Vec<AESTowerField8b>,
		univariate_zerocheck_challenge: FChallenge,
		subfield_iso_lookup: &'a SubfieldIsomorphismLookup<FChallenge>,
	) -> Self {
		let eq_ind_big_field_challenges =
			eq_ind_partial_eval(&multilinear_big_field_zerocheck_challenges);

		let univariate_round_message = univariate_round_message(
			&first_col,
			&second_col,
			&third_col,
			&eq_ind_big_field_challenges,
			&ntt_lookup,
			&small_field_zerocheck_challenges,
			univariate_zerocheck_challenge,
			subfield_iso_lookup,
		);

		Self {
			first_col,
			second_col,
			third_col,
			univariate_zerocheck_challenge,
			multilinear_big_field_zerocheck_challenges,
			small_field_zerocheck_challenges,
			subfield_iso_lookup,
			univariate_round_message,
		}
	}

	pub fn execute(&self) -> &GenericPo2UnivariatePoly<'a, FChallenge, FChallenge> {
		&self.univariate_round_message
	}

	pub fn fold_and_send_reduced_prover(
		self,
		challenge: FChallenge,
	) -> AndReductionMultilinearSumcheckProver<FChallenge> {
		let lookup = precompute_fold_lookup(challenge, self.subfield_iso_lookup);

		let proving_polys = [
			self.first_col.fold(&lookup),
			self.second_col.fold(&lookup),
			self.third_col.fold(&lookup),
		];

		let eq_ind_mul_by =
			delta_poly(self.univariate_zerocheck_challenge, SKIPPED_VARS, self.subfield_iso_lookup)
				.evaluate_at_challenge(challenge);

		let upcasted_small_field_challenges: Vec<_> = self
			.small_field_zerocheck_challenges
			.into_iter()
			.map(|i| self.subfield_iso_lookup.lookup_8b_value(i))
			.collect();

		let multilinear_zerocheck_challenges: Vec<_> = upcasted_small_field_challenges
			.iter()
			.chain(self.multilinear_big_field_zerocheck_challenges.iter())
			.copied()
			.collect();

		let sumcheck_n_vars = multilinear_zerocheck_challenges.len();
		AndReductionMultilinearSumcheckProver::new(
			proving_polys.into_iter().map(|m| m).collect_vec(),
			multilinear_zerocheck_challenges,
			self.univariate_round_message
				.evaluate_at_challenge(challenge)
				* eq_ind_mul_by.invert_or_zero(),
			sumcheck_n_vars,
			FoldDirection::LowToHigh,
		)
	}

	pub fn prove_with_transcript<TranscriptChallenger>(
		self,
		transcript: &mut ProverTranscript<TranscriptChallenger>,
	) where
		TranscriptChallenger: Challenger,
	{
		let univariate_message_coeffs = self.execute().iter_coeffs();

		for coeff in univariate_message_coeffs {
			transcript.message().write_scalar(*coeff);
		}

		let upcasted_small_field_challenges: Vec<_> = self
			.small_field_zerocheck_challenges
			.clone()
			.into_iter()
			.map(|i| self.subfield_iso_lookup.lookup_8b_value(i))
			.collect();

		let multilinear_zerocheck_challenges: Vec<_> = upcasted_small_field_challenges
			.iter()
			.chain(self.multilinear_big_field_zerocheck_challenges.iter())
			.copied()
			.collect();

		let mut sumcheck_prover = self.fold_and_send_reduced_prover(transcript.sample());

		// sumcheck
		for _ in multilinear_zerocheck_challenges {
			let round_message = sumcheck_prover.execute().unwrap();

			transcript.message().write_scalar_slice(&round_message[0].0);

			let challenge = transcript.sample();

			sumcheck_prover.fold(challenge).unwrap();
		}

		sumcheck_prover.finish().unwrap();
	}
}

#[cfg(test)]
mod test {
	use binius_field::{AESTowerField8b, AESTowerField128b, BinaryField128bPolyval, Field, PackedBinaryField128x1b, Random};
	use binius_transcript::ProverTranscript;
	use binius_verifier::config::StdChallenger;
	use rand::{SeedableRng, rngs::StdRng};
	use super::{OblongZerocheckProver};

	use crate::protocols::sumcheck::{
		and_reduction::{
			one_bit_multivariate::OneBitMultivariate,
			univariate::{
				delta::delta_poly,
				ntt_lookup::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS, precompute_lookup},
				subfield_isomorphism::SubfieldIsomorphismLookup,
				univariate_poly::{UnivariatePoly},
			},
		},
		common::SumcheckProver,
	};

	fn random_mlv(log_num_rows: usize, num_polys: usize) -> Vec<OneBitMultivariate> {
		let mut rng = StdRng::from_seed([0; 32]);

		let mut vec = Vec::with_capacity(num_polys);
		for _ in 0..num_polys {
			vec.push(
				OneBitMultivariate {
					log_num_rows,
					packed_evals: (0..1 << log_num_rows).map(|_| PackedBinaryField128x1b::random(&mut rng)).collect(),
				}
			);
		}

		vec
	}

	#[test]
	fn verify_univariate_round() {
		let log_num_rows = 10;
		let mut rng = StdRng::from_seed([0; 32]);

		let big_field_zerocheck_challenges =
			vec![BinaryField128bPolyval::random(&mut rng); (log_num_rows - SKIPPED_VARS - 3) + 1];

		let small_field_zerocheck_challenges = [
			AESTowerField8b::new(2),
			AESTowerField8b::new(4),
			AESTowerField8b::new(16),
		];

		let mlvs = random_mlv(log_num_rows, 3);
		let (first_mlv, second_mlv, third_mlv) = (mlvs[0].clone(), mlvs[1].clone(), mlvs[2].clone());

		let onto_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();

		let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

		let ntt_lookup = precompute_lookup(&onto_domain);

		// Prover is instantiated
		let prover = OblongZerocheckProver::new(
			first_mlv,
			second_mlv,
			third_mlv,
			big_field_zerocheck_challenges[1..].to_vec(),
			ntt_lookup,
			small_field_zerocheck_challenges.to_vec(),
			big_field_zerocheck_challenges[0],
			&iso_lookup,
		);

		// Prover sends its first claim
		let prover_univariate_message = prover.execute();

		let prover_poly_terms_on_oblong_hypercube = prover_univariate_message
			.iter_coeffs()
			.take(ROWS_PER_HYPERCUBE_VERTEX);

		
		assert_eq!(
			prover_poly_terms_on_oblong_hypercube.sum::<BinaryField128bPolyval>(),
			BinaryField128bPolyval::ZERO
		);

		let challenge = BinaryField128bPolyval::random(&mut rng);

		let expected_sumcheck_claim = prover_univariate_message.evaluate_at_challenge(challenge);

		let mut sumcheck_prover = prover.fold_and_send_reduced_prover(challenge);

		// let sumcheck_claim = sumcheck_prover.current_round_claim;
		let round_msg = sumcheck_prover.execute().unwrap()[0].0.clone();
		let sumcheck_claim = round_msg[0] + round_msg[1];

		let delta_mul_by = delta_poly(big_field_zerocheck_challenges[0], SKIPPED_VARS, &iso_lookup)
			.evaluate_at_challenge(challenge);

		assert_eq!(sumcheck_claim * delta_mul_by, expected_sumcheck_claim);
	}

	#[test]
	fn test_transcript_prover_runs() {
		let mut rng = StdRng::from_seed([0; 32]);

		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		let log_num_rows = 10;

		let big_field_zerocheck_challenges =
			vec![BinaryField128bPolyval::random(&mut rng); (log_num_rows - SKIPPED_VARS - 3) + 1];

		let small_field_zerocheck_challenges = [
			AESTowerField8b::new(2),
			AESTowerField8b::new(4),
			AESTowerField8b::new(16),
		];

		let mlvs = random_mlv(log_num_rows, 3);
		let (first_mlv, second_mlv, third_mlv) = (mlvs[0].clone(), mlvs[1].clone(), mlvs[2].clone());

		let onto_domain: Vec<_> = (ROWS_PER_HYPERCUBE_VERTEX..2 * ROWS_PER_HYPERCUBE_VERTEX)
			.map(|x| AESTowerField8b::new(x as u8))
			.collect();

		let iso_lookup = SubfieldIsomorphismLookup::new::<AESTowerField128b>();

		let ntt_lookup = precompute_lookup(&onto_domain);

		// Prover is instantiated
		let prover = OblongZerocheckProver::new(
			first_mlv,
			second_mlv,
			third_mlv,
			big_field_zerocheck_challenges[1..].to_vec(),
			ntt_lookup,
			small_field_zerocheck_challenges.to_vec(),
			big_field_zerocheck_challenges[0],
			&iso_lookup,
		);

		prover.prove_with_transcript(&mut prover_challenger);
	}
}
