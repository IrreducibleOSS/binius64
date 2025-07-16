use binius_transcript::fiat_shamir::{CanSample, Challenger};
use binius_transcript::VerifierTranscript;
use binius_utils::DeserializeBytes;
use binius_verifier::fri::verify::FRIVerifier;
use binius_verifier::fri::FRIParams;
use binius_verifier::merkle_tree::MerkleTreeScheme;

use crate::utils::{constants::BigField, utils::fri_fold_arities_to_is_commit_round};
use crate::utils::{
    constants::{FA, L_PRIME},
    utils::verify_sumcheck_round,
};

pub struct BigFieldBaseFoldVerifier {}

impl BigFieldBaseFoldVerifier {
    pub fn verify_transcript<VCS, TranscriptChallenger>(
        codeword_commitment: VCS::Digest,
        transcript: &mut VerifierTranscript<TranscriptChallenger>,
        evaluation_claim: BigField,
        fri_params: &FRIParams<BigField, FA>,
        vcs: &VCS,
    ) -> Result<(BigField, BigField, Vec<BigField>), String>
    where
        TranscriptChallenger: Challenger + Clone,
        VCS: MerkleTreeScheme<BigField, Digest: DeserializeBytes>,
    {
        // retrieve the challenges and further commitments from the transcript
        let mut basefold_challenges: Vec<BigField> = Vec::with_capacity(fri_params.n_fold_rounds());

        // infer sumcheck claim from transcript
        let verifier_computed_sumcheck_claim = evaluation_claim;

        // retrace footsteps through basefold
        let mut expected_sumcheck_round_claim = verifier_computed_sumcheck_claim;
        let mut round_commitments = vec![];
        let is_commit_round =
            fri_fold_arities_to_is_commit_round(fri_params.fold_arities(), L_PRIME);

        for round in 0..L_PRIME {
            let round_msg = transcript
                .message()
                .read_scalar_slice::<BigField>(3)
                .unwrap();

            let basefold_challenge = transcript.sample();

            let round_sum = round_msg[0] + round_msg[1];
            let next_claim = verify_sumcheck_round(
                round_sum,
                expected_sumcheck_round_claim,
                round_msg,
                basefold_challenge,
            );

            expected_sumcheck_round_claim = next_claim;

            basefold_challenges.push(basefold_challenge);

            if is_commit_round[round] {
                round_commitments.push(transcript.message().read().unwrap());
            }
        }

        // check c == t(r'_0, ..., r'_{\ell-1})
        // note that the prover is claiming that the final_message is [c]
        let verifier = FRIVerifier::new(
            &fri_params,
            vcs,
            &codeword_commitment,
            &round_commitments,
            &basefold_challenges,
        )
        .unwrap();

        // Get final FRI value from verifier
        let mut cloned_verifier_challenger = transcript.clone();
        let final_fri_value = verifier.verify(&mut cloned_verifier_challenger).unwrap();

        Ok((
            final_fri_value,
            expected_sumcheck_round_claim,
            basefold_challenges,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        basefold::prover::BigFieldBaseFoldProver,
        utils::{
            constants::{BigField, FA, LOG_INV_RATE, L_PRIME, NUM_TEST_QUERIES},
            eq_ind::{eq_ind_mle, eval_eq},
            utils::compute_mle_eq_sum,
        },
    };

    use binius_field::{BinaryField128b, Field, Random};
    use binius_math::{ntt::SingleThreadedNTT, ReedSolomonCode, FieldBuffer};
    use binius_prover::{
        fri::{self, CommitOutput},
        merkle_tree::prover::BinaryMerkleTreeProver,
    };
    use binius_transcript::ProverTranscript;
    use binius_verifier::{
        config::StdChallenger,
        fri::FRIParams,
        hash::{StdCompression, StdDigest},
    };
    use itertools::Itertools;
    use rand::{rngs::StdRng, SeedableRng};

    use super::BigFieldBaseFoldVerifier;

    #[test]
    #[allow(non_snake_case)]
    fn test_basefold() {
        let mut rng = StdRng::from_seed([0; 32]);

        // prover has a small field polynomial he is interested in proving an eval claim about:
        // He wishes to evaluated the small field multilinear t at the vector of large field
        // elements r.
        let packed_mle = (0..1 << L_PRIME)
            .map(|_| BigField::random(&mut rng))
            .collect_vec();

        let packed_mle = FieldBuffer::from_values(
            &packed_mle).unwrap();

        // parameters...

        let merkle_prover =
            BinaryMerkleTreeProver::<BigField, StdDigest, _>::new(StdCompression::default());

        let committed_rs_code =
            ReedSolomonCode::<FA>::new(packed_mle.log_len(), LOG_INV_RATE).unwrap();

        let fri_log_batch_size = 0;
        let fri_arities = vec![2, 1];
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
        let mut prover_challenger = ProverTranscript::new(StdChallenger::default());
        prover_challenger.message().write(&codeword_commitment);

        // random evaluation point
        let evaluation_point = (0..L_PRIME)
            .map(|_| BigField::random(&mut rng))
            .collect_vec();

        let eval_point_eq = eq_ind_mle(&evaluation_point);
        // evaluate small field multilinear at the evaluation point
        // It is assumed the prover and verifier already know the evaluation claim
        let evaluation_claim =
            compute_mle_eq_sum(packed_mle.as_ref(), eval_point_eq.as_ref());

        // Instantiate basefold
        let basefold_pcs_prover = BigFieldBaseFoldProver::new(
            &ntt,
            &merkle_prover,
            &fri_params,
            &codeword,
            &codeword_committed,
            packed_mle,
            eval_point_eq,
            evaluation_claim,
        )
        .unwrap();

        // prove non-interactively
        basefold_pcs_prover.prove_with_transcript(evaluation_claim, &mut prover_challenger);

        // convert the finalized prover transcript into a verifier transcript
        let mut verifier_challenger = prover_challenger.into_verifier();

        let verifier_codeword_commitment = verifier_challenger.message().read().unwrap();

        // REST OF THE PROTOCOL VERIFIED HERE

        // verify non-interactively
        let (fri_final_value, sumcheck_final_claim, basefold_challenges) =
            BigFieldBaseFoldVerifier::verify_transcript(
                verifier_codeword_commitment,
                &mut verifier_challenger,
                evaluation_claim,
                &fri_params,
                merkle_prover.scheme(),
            )
            .unwrap();

        // basefold is transparent-polynomial-agnostic, meaning that basefold demands a claim on the transparent polynomial be verified
        assert_eq!(
            fri_final_value * eval_eq(&evaluation_point, &basefold_challenges),
            sumcheck_final_claim
        );
    }
}
