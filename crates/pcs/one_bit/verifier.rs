use binius_transcript::{VerifierTranscript, fiat_shamir::{Challenger, CanSample}};
use binius_utils::DeserializeBytes;
use binius_verifier::{fri::FRIParams, merkle_tree::MerkleTreeScheme};
use itertools::Itertools;

use crate::{
    basefold::verifier::BigFieldBaseFoldVerifier,
    utils::{
        constants::{BigField, SmallField, KAPPA},
        eq_ind::eq_ind_mle,
        utils::{compute_expected_sumcheck_claim, compute_mle_eq_sum, construct_s_hat_u},
    },
};
use crate::{ring_switch::eq_ind_eval::eval_rs_eq, utils::constants::FA};

pub struct OneBitPCSVerifier {}

impl OneBitPCSVerifier {
    pub fn verify_transcript<TranscriptChallenger, VCS>(
        codeword_commitment: VCS::Digest,
        transcript: &mut VerifierTranscript<TranscriptChallenger>,
        evaluation_claim: BigField,
        eval_point: &Vec<BigField>,
        fri_params: &FRIParams<BigField, FA>,
        vcs: &VCS,
    ) -> Result<(), String>
    where
        TranscriptChallenger: Challenger + Clone,
        VCS: MerkleTreeScheme<BigField, Digest: DeserializeBytes>,
    {
        // retrieve partial eval of t' at high degree variables
        let s_hat_v = transcript
            .message()
            .read_scalar_slice::<BigField>(1 << KAPPA)
            .unwrap();

        // verifier checks initial message
        let (eval_point_low, _) = eval_point.split_at(KAPPA);
        assert_eq!(
            evaluation_claim,
            compute_mle_eq_sum(&s_hat_v, eq_ind_mle(&eval_point_low).as_ref())
        );

        // basis decompose/recombine s_hat_v across opposite dimension
        let s_hat_u: Vec<BigField> =
            construct_s_hat_u::<SmallField, BigField>( s_hat_v);

        // retrieve batching scalars
        let batching_scalars: Vec<BigField> =
            OneBitPCSVerifier::verifier_samples_batching_scalars(transcript);

        let verifier_eq_r_double_prime = eq_ind_mle(&batching_scalars);

        // infer sumcheck claim from transcript
        let verifier_computed_sumcheck_claim = compute_expected_sumcheck_claim::<
            SmallField,
            BigField,
        >(&s_hat_u, verifier_eq_r_double_prime.as_ref());

        let (fri_final_value, sumcheck_final_claim, basefold_challenges) =
            BigFieldBaseFoldVerifier::verify_transcript(
                codeword_commitment,
                transcript,
                verifier_computed_sumcheck_claim,
                &fri_params,
                vcs,
            )
            .unwrap();
        // Final Basefold Verification
        let (_, eval_point_high) = eval_point.split_at(KAPPA);
        let rs_eq_at_basefold_challenges_verifier = eval_rs_eq(
            eval_point_high,
            &basefold_challenges,
            &eq_ind_mle(&batching_scalars).as_ref(),
        );

        assert_eq!(
            fri_final_value * rs_eq_at_basefold_challenges_verifier,
            sumcheck_final_claim
        );

        Ok(())
    }

    pub fn verifier_samples_batching_scalars<TranscriptChallenger>(
        transcript: &mut VerifierTranscript<TranscriptChallenger>,
    ) -> Vec<BigField>
    where
        TranscriptChallenger: Challenger,
    {
        (0..KAPPA).map(|_| transcript.sample()).collect_vec()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        one_bit::{prover::OneBitPCSProver, verifier::OneBitPCSVerifier},
        utils::{
            constants::{
                BigField, SmallField, FA, L, LOG_INV_RATE, L_PRIME, NUM_TEST_QUERIES,
            },
            eq_ind::eq_ind_mle,
            utils::lift_small_to_large_field,
            utils::{compute_mle_eq_sum, large_field_mle_to_small_field_mle},
        },
    };

    use binius_field::{BinaryField128b, Field, Random};
    use binius_math::{ntt::SingleThreadedNTT, ReedSolomonCode, FieldBuffer};
    use binius_prover::{merkle_tree::prover::BinaryMerkleTreeProver, fri::{CommitOutput, self}};
    use binius_transcript::ProverTranscript;
    use binius_verifier::{fri::FRIParams, config::StdChallenger, hash::{StdCompression, StdDigest}};
    use itertools::Itertools;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    #[allow(non_snake_case)]
    fn test_ring_switched_pcs() {
        let mut rng = StdRng::from_seed([0; 32]);

        // prover has a small field polynomial he is interested in proving an eval claim about:
        // He wishes to evaluated the small field multilinear t at the vector of large field
        // elements r.
        let packed_mle = (0..1 << L_PRIME)
            .map(|_| BigField::random(&mut rng))
            .collect_vec();

        let lifted_small_field_mle = lift_small_to_large_field(
            &large_field_mle_to_small_field_mle::<SmallField, BigField>(&packed_mle),
        );

        let packed_mle = FieldBuffer::from_values(
            &packed_mle
        ).unwrap();

        // parameters...

        let merkle_prover =
            BinaryMerkleTreeProver::<BinaryField128b, StdDigest, _>::new(StdCompression::default());

        let committed_rs_code =
            ReedSolomonCode::<FA>::new(packed_mle.log_len(), LOG_INV_RATE).unwrap();

        let fri_log_batch_size = 0;
        let fri_arities = vec![1; packed_mle.log_len() - 1];
        let fri_params = FRIParams::new(
            committed_rs_code,
            fri_log_batch_size,
            fri_arities,
            NUM_TEST_QUERIES,
        )
        .unwrap();

        // Commit packed mle codeword to transcript
        let ntt = SingleThreadedNTT::new(fri_params.rs_code().log_len()).unwrap();
        let CommitOutput {
            commitment: codeword_commitment,
            committed: codeword_committed,
            codeword,
        } = fri::commit_interleaved(
            fri_params.rs_code(),
            &fri_params,
            &ntt,
            &merkle_prover,
            packed_mle.as_ref(),
        )
        .unwrap();

        // commit codeword in prover transcript
        let mut prover_challenger = ProverTranscript::new(StdChallenger::default());;
        prover_challenger.message().write(&codeword_commitment);

        // random evaluation point
        let evaluation_point = (0..L).map(|_| BigField::random(&mut rng)).collect_vec();

        // evaluate small field multilinear at the evaluation point
        // It is assumed the prover and verifier already know the evaluation claim
        let evaluation_claim = compute_mle_eq_sum(
            &lifted_small_field_mle,
            &eq_ind_mle(&evaluation_point).as_ref(),
        );

        // Instantiate ring switch pcs
        let ring_switch_pcs_prover = OneBitPCSProver::new(
            packed_mle.clone(),
            evaluation_claim,
            evaluation_point.clone(),
        )
        .unwrap();

        // prove non-interactively
        ring_switch_pcs_prover.prove_with_transcript(
            &mut prover_challenger,
            &ntt,
            &merkle_prover,
            &fri_params,
            &codeword,
            &codeword_committed,
        );

        // convert the finalized prover transcript into a verifier transcript
        let mut verifier_challenger = prover_challenger.into_verifier();
        // retrieve the initial commitment from the transcript
        let codeword_commitment = verifier_challenger.message().read().unwrap();

        // REST OF THE PROTOCOL IS VERIFIED HERE

        // verify non-interactively
        OneBitPCSVerifier::verify_transcript(
            codeword_commitment,
            &mut verifier_challenger,
            evaluation_claim,
            &evaluation_point,
            &fri_params,
            merkle_prover.scheme(),
        )
        .unwrap();
    }
}
