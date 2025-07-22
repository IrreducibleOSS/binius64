use binius_field::{AESTowerField8b, Field};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};

use crate::protocols::sumcheck::and_reduction::{
	sumcheck_prover::verify_round,
	univariate::{
		delta::delta_poly,
		ntt_lookup::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS},
		subfield_isomorphism::SubfieldIsomorphismLookup,
		univariate_poly::{GenericPo2UnivariatePoly, UnivariatePoly},
	},
};

pub struct OblongZerocheckVerifier {}

impl OblongZerocheckVerifier {
	pub fn verify_with_transcript<F, FIntermediateForLookup, TranscriptChallenger>(
		all_zerocheck_challenges: &[F],
		transcript: &mut VerifierTranscript<TranscriptChallenger>,
	) -> (Vec<F>, F)
	where
		TranscriptChallenger: Challenger,
		F: Field + From<FIntermediateForLookup>,
		FIntermediateForLookup: Field + From<AESTowerField8b>,
	{
		let (univariate_zerocheck_challenge, multilinear_zerocheck_challenges) =
			all_zerocheck_challenges.split_at(1);
		let univariate_zerocheck_challenge = univariate_zerocheck_challenge[0];
		let iso_lookup = SubfieldIsomorphismLookup::new::<FIntermediateForLookup>();
		let univariate_message_coeffs = transcript
			.message()
			.read_scalar_slice(4 * ROWS_PER_HYPERCUBE_VERTEX)
			.unwrap();

		assert_eq!(
			univariate_message_coeffs
				.iter()
				.take(ROWS_PER_HYPERCUBE_VERTEX)
				.sum::<F>(),
			F::ZERO
		);

		let univariate_message =
			GenericPo2UnivariatePoly::new(univariate_message_coeffs, &iso_lookup);
		let univariate_sumcheck_challenge = transcript.sample();

		let delta_mul_by = delta_poly(univariate_zerocheck_challenge, SKIPPED_VARS, &iso_lookup)
			.evaluate_at_challenge(univariate_sumcheck_challenge);

		let mut sumcheck_claim = univariate_message
			.evaluate_at_challenge(univariate_sumcheck_challenge)
			* delta_mul_by.invert_or_zero();

		let mut sumcheck_challenges = vec![];

		for this_round_zerocheck_challenge in multilinear_zerocheck_challenges.iter() {
			let round_message: Vec<F> = transcript.message().read_scalar_slice(3).unwrap();

			let challenge: F = transcript.sample();

			sumcheck_claim = verify_round(
				sumcheck_claim,
				round_message.clone(),
				challenge,
				*this_round_zerocheck_challenge,
			);

			sumcheck_challenges.push(challenge);
		}

		(sumcheck_challenges, sumcheck_claim)
	}
}

#[cfg(test)]
mod test {
	use binius_field::{
		AESTowerField8b, AESTowerField128b, BinaryField128bPolyval, PackedBinaryField128x1b, Random,
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::config::StdChallenger;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::protocols::sumcheck::and_reduction::{
		one_bit_multivariate::OneBitMultivariate, univariate::ntt_lookup::precompute_lookup,
		zerocheck_prover::OblongZerocheckProver,
	};

	#[test]
	fn test_transcript_prover_runs() {
		let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
		let log_num_rows = 10;
		let mut rng = StdRng::from_seed([0; 32]);
		let big_field_zerocheck_challenges =
			vec![BinaryField128bPolyval::random(&mut rng); (log_num_rows - SKIPPED_VARS - 3) + 1];

		let small_field_zerocheck_challenges = [
			AESTowerField8b::new(2),
			AESTowerField8b::new(4),
			AESTowerField8b::new(16),
		];
		let first_mlv = OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|_| PackedBinaryField128x1b::random(&mut rng))
				.collect(),
		};

		let second_mlv = OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|_| PackedBinaryField128x1b::random(&mut rng))
				.collect(),
		};

		let third_mlv = OneBitMultivariate {
			log_num_rows,
			packed_evals: (0..1 << log_num_rows)
				.map(|i| first_mlv.packed_evals[i] * second_mlv.packed_evals[i])
				.collect(),
		};

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

		let mut verifier_challenger = prover_challenger.into_verifier();

		let mut all_zerocheck_challenges = vec![];

		all_zerocheck_challenges.push(big_field_zerocheck_challenges[0]);

		for small_field_challenge in small_field_zerocheck_challenges {
			all_zerocheck_challenges.push(iso_lookup.lookup_8b_value(small_field_challenge));
		}

		for big_field_challenge in &big_field_zerocheck_challenges[1..] {
			all_zerocheck_challenges.push(*big_field_challenge);
		}

		// TODO: test the evaluation claim that gets spat out with an eq dot-product
		let _ = OblongZerocheckVerifier::verify_with_transcript::<_, AESTowerField128b, _>(
			&all_zerocheck_challenges,
			&mut verifier_challenger,
		);
	}
}
