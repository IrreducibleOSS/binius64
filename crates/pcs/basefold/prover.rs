use crate::{
    multilinear_sumcheck::{
        field_buffer_multilinear_sumcheck::{FoldDirection, MultilinearSumcheckProver},
        sumcheck_prover::SumcheckProver,
    },
    utils::{
        constants::L_PRIME,
        utils::verify_sumcheck_round,
    },
};



use binius_field::{
    BinaryField, ExtensionField, TowerField, as_packed_field::PackScalar, underlier::WithUnderlier,
};
use binius_math::{ntt::AdditiveNTT, FieldBuffer};
use binius_prover::{fri::{FRIFolder, FoldRoundOutput}, merkle_tree::MerkleTreeProver};
use binius_transcript::{ProverTranscript, fiat_shamir::{Challenger, CanSample}};
use binius_utils::SerializeBytes;
use binius_verifier::{merkle_tree::MerkleTreeScheme, fri::FRIParams};
use std::vec;

pub struct BigFieldBaseFoldProver<'a, F, FA, NTT, MerkleProver, VCS>
where
    F: TowerField + ExtensionField<FA> + BinaryField,
    FA: BinaryField,
    NTT: AdditiveNTT<FA> + Sync,
    MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
    VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
{
    sumcheck_prover: MultilinearSumcheckProver<F>,
    fri_folder: FRIFolder<'a, F, FA, F, NTT, MerkleProver, VCS>,
}

impl<'a, F, FA, NTT, MerkleProver, VCS> BigFieldBaseFoldProver<'a, F, FA, NTT, MerkleProver, VCS>
where
    F: TowerField + ExtensionField<FA>,
    FA: BinaryField,
    NTT: AdditiveNTT<FA> + Sync,
    MerkleProver: MerkleTreeProver<F, Scheme = VCS>,
    VCS: MerkleTreeScheme<F, Digest: SerializeBytes>,
    <F as WithUnderlier>::Underlier: PackScalar<FA>,
{
    pub fn new(
        ntt: &'a NTT,
        merkle_prover: &'a MerkleProver,
        fri_params: &'a FRIParams<F, FA>,
        committed_codeword: &'a [F],
        committed: &'a MerkleProver::Committed,
        packed_mle_owned: FieldBuffer<F>,
        transparent_poly_mle: FieldBuffer<F>,
        claim: F,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let fri_folder = FRIFolder::new(
            fri_params,
            ntt,
            merkle_prover,
            committed_codeword,
            committed,
        )
        .unwrap();

        let log_n = packed_mle_owned.log_len();
        let sumcheck_prover = MultilinearSumcheckProver::<F>::new(
            vec![packed_mle_owned, transparent_poly_mle],
            claim,
            log_n,
            FoldDirection::LowToHigh,
        );

        Ok(Self {
            sumcheck_prover,
            fri_folder,
        })
    }

    pub fn execute(&self) -> Vec<F> {
        self.sumcheck_prover.round_message()
    }

    pub fn fold(
        &mut self,
        challenge: F,
    ) -> Result<
        FoldRoundOutput<<VCS as MerkleTreeScheme<F>>::Digest>,
        binius_prover::fri::Error
    > {
        self.sumcheck_prover.fold(challenge);

        self.fri_folder.execute_fold_round(challenge)
    }

    pub fn prove_with_transcript<TranscriptChallenger>(
        mut self,
        sumcheck_claim: F,
        transcript: &mut ProverTranscript<TranscriptChallenger>,
    ) where
        TranscriptChallenger: Challenger,
    {
        let mut basefold_challenges = vec![];
        let mut expected_sumcheck_round_claim = sumcheck_claim;

        let mut round_commitments = vec![];
        for _ in 0..L_PRIME {
            // Execute FRI-Binius round
            let round_msg = self.execute();

            transcript.message().write_scalar_slice(&round_msg);

            // Get challenge from transcript (fiat shamir)
            let basefold_challenge = transcript.sample();
            basefold_challenges.push(basefold_challenge);

            // Verify sumcheck round
            let round_sum = round_msg[0] + round_msg[1];
            let next_claim: F = verify_sumcheck_round(
                round_sum,
                expected_sumcheck_round_claim,
                round_msg,
                basefold_challenge,
            );
            expected_sumcheck_round_claim = next_claim;

            // prover folds
            let next_round_commitment = self.fold(basefold_challenge).unwrap();

            // prover writes commitment to transcript
            match next_round_commitment {
                FoldRoundOutput::NoCommitment => {}
                FoldRoundOutput::Commitment(round_commitment) => {
                    transcript.message().write(&round_commitment);
                    round_commitments.push(round_commitment);
                }
            }
        }
        // finish proof, finalizing transcript, proving FRI queries
        self.finish(transcript)
    }

    pub fn finish<TranscriptChallenger>(
        self,
        prover_challenger: &mut ProverTranscript<TranscriptChallenger>,
    ) where
        TranscriptChallenger: Challenger,
    {
        // finish proof, finalizing transcript
        self.fri_folder.finish_proof(prover_challenger).unwrap();
    }
}
