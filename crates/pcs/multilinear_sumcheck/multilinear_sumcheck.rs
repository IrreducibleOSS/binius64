use crate::multilinear_sumcheck::sumcheck_prover::SumcheckProver;
use crate::utils::big_field_multilinear::{BigFieldMultilinear, field_buffer_to_mle, mle_to_field_buffer};
use binius_math::FieldBuffer;
use binius_field::Field;

use crate::multilinear_sumcheck::field_buffer_multilinear_sumcheck as new_sumcheck;

// ! Big Field MLE Sumcheck Prover

pub enum FoldDirection {
    LowToHigh,
    HighToLow,
}

pub struct MultilinearSumcheckProver<BF: Field> {
    pub multilinears: Vec<BigFieldMultilinear<BF>>,
    pub overall_claim: BF,
    pub log_n: usize,
    pub current_round_claim: BF,
    pub fold_direction: FoldDirection,
    pub new_sumcheck_prover: new_sumcheck::MultilinearSumcheckProver<BF>,
}

impl<BF: Field> MultilinearSumcheckProver<BF> {
    pub fn new(
        multilinears: Vec<BigFieldMultilinear<BF>>,
        overall_claim: BF,
        log_n: usize,
        fold_direction: FoldDirection,
    ) -> Self {

        let field_buffer_multilinears = multilinears
            .iter()
            .map(
                |mle| mle_to_field_buffer(mle.clone()).unwrap()
            ).collect::<Vec<FieldBuffer<BF>>>();

        let new_sumcheck_prover = match fold_direction {
            FoldDirection::LowToHigh => {
                new_sumcheck::MultilinearSumcheckProver::new(
                    field_buffer_multilinears,
                    overall_claim,
                    log_n,
                    new_sumcheck::FoldDirection::LowToHigh,
                )
            }
            FoldDirection::HighToLow => {
                 new_sumcheck::MultilinearSumcheckProver::new(
                    field_buffer_multilinears,
                    overall_claim,
                    log_n,
                    new_sumcheck::FoldDirection::HighToLow,
                )
            }
        };

        Self {
            multilinears,
            overall_claim,
            log_n,
            current_round_claim: overall_claim,
            fold_direction,
            new_sumcheck_prover,
        }
    }

    // sums the composition of 2 multilinears A * B
    pub fn sum_composition(a: &BigFieldMultilinear<BF>, b: &BigFieldMultilinear<BF>) -> BF {

        new_sumcheck::MultilinearSumcheckProver::sum_composition(
            &mle_to_field_buffer(a.clone()).unwrap(),
            &mle_to_field_buffer(b.clone()).unwrap()
        ).unwrap()
    }
}

impl<BF: Field> SumcheckProver<BF> for MultilinearSumcheckProver<BF> {
    fn fold(&mut self, challenge: BF) {

        self.new_sumcheck_prover.fold(challenge);

        let a = self.new_sumcheck_prover.multilinears[0].clone();
        let b = self.new_sumcheck_prover.multilinears[1].clone();

        self.multilinears[0] = field_buffer_to_mle(a).unwrap();
        self.multilinears[1] = field_buffer_to_mle(b).unwrap();
    }

    fn round_message(&self) -> Vec<BF> {
        self.new_sumcheck_prover.round_message()
    }

    fn final_eval_claims(self) -> Vec<BF> {
        self.new_sumcheck_prover.final_eval_claims()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use binius_field::{BinaryField128b, Random};
    use rand::{SeedableRng, rngs::StdRng};
    use crate::utils::eq_ind::eq_ind;
    use std::array;
    use crate::utils::utils::{evaluate_round_polynomial_at, verify_sumcheck_round};

    type BF = BinaryField128b;

    fn random_challenge() -> BF {
        let mut rng = StdRng::from_seed([0; 32]);
        BF::random(&mut rng)
    }

    fn two_random_multilinears(log_n: usize) -> [BigFieldMultilinear<BF>; 2] {
        let mut rng = StdRng::from_seed([0; 32]);
        let n = 1 << log_n;
        array::from_fn(|_| BigFieldMultilinear {
            n_vars: log_n,
            packed_evals: (0..n).map(|_| BF::random(&mut rng)).collect::<Vec<BF>>(),
        })
    }

    // runs sumcheck interactive protocol for multilinear composition (A * B - C) * eq_r
    // eq_r is the multilinear equality indicator for some vector of log_n zerocheck challenges
    pub fn multilinear_sumcheck(prover: &mut MultilinearSumcheckProver<BF>) -> (BF, Vec<BF>) {
        let log_n = prover.log_n;

        let mut expected_next_round_claim = prover.overall_claim;
        let mut sumcheck_challenges = Vec::with_capacity(log_n);

        for _ in 0..log_n {

            // verifier sends sumcheck challenge
            let sumcheck_challenge = random_challenge();
            sumcheck_challenges.push(sumcheck_challenge);

            // prover computes round message
            let round_msg = prover.round_message();

            // verifier checks round message against claim
            expected_next_round_claim = verify_sumcheck_round(
                prover.current_round_claim,
                expected_next_round_claim,
                round_msg.clone(),
                sumcheck_challenge,
            );

            // prover sets next round claim
            prover.current_round_claim =
                evaluate_round_polynomial_at(sumcheck_challenge, round_msg.clone());

            // prover folds challenge into multilinear
            prover.fold(sumcheck_challenge);
        }

        (expected_next_round_claim, sumcheck_challenges)
    }

    fn run_sumcheck_interactive_protocol(
        multilinears: [BigFieldMultilinear<BF>; 2],
        fold_direction: FoldDirection
    ) {
        let log_n = multilinears[0].n_vars;

        let mle_packed_evals_copied: [_; 2] =
            array::from_fn(|i| multilinears[i].packed_evals.to_vec());

        // compute overall sumcheck claim for composition A * eq_r
        let overall_claim =
            MultilinearSumcheckProver::sum_composition(&multilinears[0], &multilinears[1]);

        // create multilinear sumcheck prover
        let mut prover = MultilinearSumcheckProver::new(
            multilinears.to_vec(),
            overall_claim,
            log_n,
            fold_direction,
        );

        // run sumcheck
        let (final_sumcheck_msg, sumcheck_challenges) = multilinear_sumcheck(&mut prover);

        // gather final eval claims
        let _final_eval_claims = prover.final_eval_claims();

        // test that the final sumcheck message is indeed the evaluation of the
        // multilinear at the sumcheck challenges
        let sumcheck_challenges_tensor_expansion: BigFieldMultilinear<BF> =
            eq_ind(&sumcheck_challenges.into_iter().rev().collect::<Vec<_>>());
        let (mut eval_a, mut eval_b) = (BF::ZERO, BF::ZERO);
        for i in 0..1 << log_n {
            eval_a += mle_packed_evals_copied[0][i]
                * sumcheck_challenges_tensor_expansion.packed_evals[i];
            eval_b += mle_packed_evals_copied[1][i]
                * sumcheck_challenges_tensor_expansion.packed_evals[i];
        }

        assert_eq!(eval_a * eval_b, final_sumcheck_msg);
    }
    
    #[test]
    fn test_sumcheck_low_to_high() {
        let log_n = 5;
        let multilinears = two_random_multilinears(log_n);
        run_sumcheck_interactive_protocol(multilinears, FoldDirection::LowToHigh);
    }

    #[test]
    fn test_sumcheck_high_to_low() {
        let log_n = 5;
        let multilinears = two_random_multilinears(log_n);
        run_sumcheck_interactive_protocol(multilinears, FoldDirection::HighToLow);
    }

    #[test]
    fn test_composition_even_odd_sum() {
        let mut rng = StdRng::from_seed([0; 32]);

        let log_n = 5;
        let n = 1 << log_n;

        let multilinear = BigFieldMultilinear {
            n_vars: log_n,
            packed_evals: (0..n)
                .map(|_| BF::random(&mut rng))
                .collect::<Vec<BF>>(),
        };

        let challenges = (0..log_n)
            .map(|_| BF::random(&mut rng))
            .collect::<Vec<BF>>();

        let eq_r: BigFieldMultilinear<BF> = eq_ind(&challenges.clone());

        let overall_sum = MultilinearSumcheckProver::sum_composition(&multilinear, &eq_r);

        // produce g(0), g(1) by summing over evals where first var is 0, 1
        let mut g_of_zero = BF::ZERO;
        let mut g_of_one = BF::ZERO;
        for i in 0..n {
            let a = multilinear.packed_evals[i];
            let eq_r_i = eq_r.packed_evals[i];

            if i % 2 == 0 {
                g_of_zero += a * eq_r_i;
            } else {
                g_of_one += a * eq_r_i;
            }
        }

        assert_eq!(overall_sum, g_of_zero + g_of_one);
    }
}