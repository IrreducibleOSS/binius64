use binius_field::{BinaryField128bPolyval, Field, arithmetic_traits::TaggedInvertOrZero, AESTowerField128b, AESTowerField8b};
use binius_transcript::{fiat_shamir::{Challenger, CanSample}, VerifierTranscript};

use crate::and_reduction::{utils::{subfield_isomorphism::SubfieldIsomorphismLookup, constants::{ROWS_PER_HYPERCUBE_VERTEX, SKIPPED_VARS}, verify_sumcheck_round::verify_round}, univariate::{univariate_poly::{GenericPo2UnivariatePoly, UnivariatePoly}, delta::delta_poly}};

pub struct OblongZerocheckVerifier {}

impl OblongZerocheckVerifier {
    pub fn verify_with_transcript<F, FIntermediateForLookup, TranscriptChallenger>(
        all_zerocheck_challenges: &[F],
        transcript: &mut VerifierTranscript<TranscriptChallenger>,
    )->(Vec<F>, F) where
        TranscriptChallenger: Challenger,
        F: Field + From<FIntermediateForLookup>,
        FIntermediateForLookup: Field+ From<AESTowerField8b>
    {
        let (univariate_zerocheck_challenge, multilinear_zerocheck_challenges) = all_zerocheck_challenges.split_at(1);
        let univariate_zerocheck_challenge = univariate_zerocheck_challenge[0];
        let iso_lookup = SubfieldIsomorphismLookup::new::<FIntermediateForLookup>();
        let univariate_message_coeffs = transcript.message().read_scalar_slice(4*ROWS_PER_HYPERCUBE_VERTEX).unwrap();

        assert_eq!(univariate_message_coeffs.iter().take(ROWS_PER_HYPERCUBE_VERTEX).sum::<F>(),F::ZERO);

        let univariate_message = GenericPo2UnivariatePoly::new(univariate_message_coeffs, &iso_lookup);
        let univariate_sumcheck_challenge = transcript.sample();

        let delta_mul_by = delta_poly(univariate_zerocheck_challenge, SKIPPED_VARS, &iso_lookup)
        .evaluate_at_challenge(univariate_sumcheck_challenge);

        let mut sumcheck_claim = univariate_message.evaluate_at_challenge(univariate_sumcheck_challenge) * delta_mul_by.invert_or_zero();

        let mut sumcheck_challenges = vec![];
        // zerocheck challenges are reversed because they are considered in high-to-low order
        for this_round_zerocheck_challenge in multilinear_zerocheck_challenges.into_iter().rev(){
            let round_message: Vec<F> = transcript.message().read_scalar_slice(3).unwrap();

            let challenge: F = transcript.sample();

            sumcheck_claim = verify_round(
                sumcheck_claim,
                round_message.clone(),
                challenge,
                *this_round_zerocheck_challenge, // eq_ind expects zerocheck challenges in rev order
            );
            
            sumcheck_challenges.push(challenge);
        }

        (sumcheck_challenges, sumcheck_claim)
    }
}