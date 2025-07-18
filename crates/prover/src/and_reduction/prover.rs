// use crate::_prover::SumcheckProver;
use crate::and_reduction::mle::BigFieldMultilinear;
use binius_field::{BinaryField128bPolyval, Field, Random, ExtensionField, AESTowerField128b};
use rand::{SeedableRng, rngs::StdRng};
use std::vec;
use binius_maybe_rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator, IntoParallelRefIterator, ParallelSliceMut, IntoParallelIterator};

// use binius_math::multilinear::tensor_prod_eq_ind;
pub trait SumcheckProver<F: Field> {
    fn fold(&mut self, challenge: F);

    fn round_message(&self) -> Vec<F>;

    fn final_eval_claims(self) -> Vec<F>;
}


pub fn eq_ind<F: Field, BF>(zerocheck_challenges: &[F]) -> BigFieldMultilinear<BF>
where
    BF: ExtensionField<F> + From<AESTowerField128b>,
{
    let mut mle = bytemuck::zeroed_vec(1 << zerocheck_challenges.len());

    let _span = tracing::debug_span!("eq ind").entered();

    mle[0] = BF::ONE;
    for (curr_log_len, challenge) in zerocheck_challenges.iter().rev().enumerate() {
        let _span = tracing::debug_span!("compute eq_ind for curr log len").entered();

        let (mle_lower, mle_upper) = mle.split_at_mut(1 << curr_log_len);

        mle_lower
            .par_iter_mut()
            .zip(mle_upper.par_iter_mut())
            .for_each(|(low, up)| {
                let multiplied = *low * *challenge;
                *up = multiplied;
                *low -= multiplied;
            });
    }

    BigFieldMultilinear {
        n_vars: zerocheck_challenges.len(),
        packed_evals: mle,
    }
}

type BF = BinaryField128bPolyval;

// enum for low to high and high to low indices
pub enum FoldDirection {
    LowToHigh,
    HighToLow,
}
pub struct MultilinearSumcheckProver {
    pub multilinears: Vec<BigFieldMultilinear<BF>>,
    pub overall_claim: BF,
    pub log_n: usize,

    pub zerocheck_challenges: Vec<BF>,

    pub final_eval_claims: Vec<BF>,
    pub current_round_claim: BF,
    pub eq_factor: BF,
    pub fold_direction: FoldDirection,
}

impl MultilinearSumcheckProver {
    pub fn new(
        multilinears: Vec<BigFieldMultilinear<BF>>,
        zerocheck_challenges: Vec<BF>,
        overall_claim: BF,
        log_n: usize,
        fold_direction: FoldDirection,
    ) -> Self {
        debug_assert_eq!(multilinears.len(), 3);

        // compute eq indicator from zerocheck challenges, add to multilinears for folding
        let eq_r: BigFieldMultilinear<BF> = eq_ind(&zerocheck_challenges);
        let mut multilinears = multilinears;
        multilinears.push(eq_r);

        Self {
            multilinears,
            overall_claim,
            log_n,
            zerocheck_challenges,
            final_eval_claims: vec![],
            current_round_claim: overall_claim,
            eq_factor: BF::ONE,
            fold_direction,
        }
    }

    // sums the composition of 4 multilinears (A * B - C) * D
    pub fn sum_composition(
        a: &BigFieldMultilinear<BF>,
        b: &BigFieldMultilinear<BF>,
        c: &BigFieldMultilinear<BF>,
        d: &BigFieldMultilinear<BF>,
    ) -> BF {
        let _span = tracing::debug_span!("sum composition (A * B - C) * eq_r").entered();

        let n = 1 << a.n_vars;
        let mut sum = BF::ZERO;
        for i in 0..n {
            let a_i = a.packed_evals[i];
            let b_i = b.packed_evals[i];
            let c_i = c.packed_evals[i];
            let d_i = d.packed_evals[i];

            sum += (a_i * b_i - c_i) * d_i;
        }

        sum
    }

    // sequential round message computation
    fn round_msg_seq(&self) -> Vec<BF> {
        let _span = tracing::debug_span!("round message sequential").entered();

        let log_n = self.multilinears[0].n_vars;
        let n = 1 << log_n;
        let n_half = n >> 1;

        // compute indices for either high to low or low to high
        let compute_idx: fn((usize, usize)) -> (usize, usize) = match self.fold_direction {
            FoldDirection::LowToHigh => |(j, _)| (2 * j, 2 * j + 1),
            FoldDirection::HighToLow => |(j, n)| (j, n + j),
        };

        // compute g(0), and leading coeff of g(x)
        let (mut g_of_zero, mut g_leading_coeff) = (BF::ZERO, BF::ZERO);
        for j in 0..n_half {
            let a = &self.multilinears[0].packed_evals;
            let b = &self.multilinears[1].packed_evals;
            let c = &self.multilinears[2].packed_evals;
            let d = &self.multilinears[3].packed_evals;

            let (lower_idx, upper_idx) = compute_idx((j, n_half));

            let a_lower = a[lower_idx];
            let b_lower = b[lower_idx];
            let c_lower = c[lower_idx];
            let d_lower = d[lower_idx];

            let a_upper = a[upper_idx];
            let b_upper = b[upper_idx];
            let d_upper = d[upper_idx];

            g_of_zero += (a_lower * b_lower - c_lower) * d_lower;

            g_leading_coeff += (a_lower + a_upper) * (b_lower + b_upper) * (d_lower + d_upper);
        }

        g_of_zero *= self.eq_factor;
        g_leading_coeff *= self.eq_factor;

        // g(1) = current_round_claim - g(0)
        let g_of_one = self.current_round_claim - g_of_zero;

        // return round message
        let mut round_msg = Vec::with_capacity(3);
        round_msg.extend([g_of_zero, g_of_one, g_leading_coeff]);
        round_msg
    }

    // sequential fold
    fn fold_seq(&mut self, challenge: BF) {
        let _span = tracing::debug_span!("fold inplace sequential").entered();

        // compute indices for either high to low or low to high
        let compute_idx: fn((usize, usize)) -> (usize, usize) = match self.fold_direction {
            FoldDirection::LowToHigh => |(j, _)| (2 * j, 2 * j + 1),
            FoldDirection::HighToLow => |(j, n)| (j, n + j),
        };

        let n = 1 << self.multilinears[0].n_vars;
        let n_half = n >> 1;
        for j in 0..n_half {
            let (low_idx, high_idx) = compute_idx((j, n_half));

            let a_even = self.multilinears[0].packed_evals[low_idx];
            let b_even = self.multilinears[1].packed_evals[low_idx];
            let c_even = self.multilinears[2].packed_evals[low_idx];
            let d_even = self.multilinears[3].packed_evals[low_idx];

            let a_odd = self.multilinears[0].packed_evals[high_idx];
            let b_odd = self.multilinears[1].packed_evals[high_idx];
            let c_odd = self.multilinears[2].packed_evals[high_idx];
            let d_odd = self.multilinears[3].packed_evals[high_idx];

            // (1 - r) * even + r * odd == even + r * (odd - even)
            self.multilinears[0].packed_evals[j] = a_even + challenge * (a_odd - a_even);
            self.multilinears[1].packed_evals[j] = b_even + challenge * (b_odd - b_even);
            self.multilinears[2].packed_evals[j] = c_even + challenge * (c_odd - c_even);
            self.multilinears[3].packed_evals[j] = d_even + d_odd;
        }
        // remove last 1 << n-1 elements from each multilinear
        for i in 0..self.multilinears.len() {
            self.multilinears[i].packed_evals.truncate(n >> 1);
            self.multilinears[i].n_vars -= 1;
        }
    }

    // parallel round message computation
    fn round_msg_par(&self) -> Vec<BF> {
        let _span = tracing::debug_span!("round message parallel").entered();

        let log_n = self.multilinears[0].n_vars;
        let n = 1 << log_n;
        let n_half = n >> 1;

        let a = &self.multilinears[0].packed_evals;
        let b = &self.multilinears[1].packed_evals;
        let c = &self.multilinears[2].packed_evals;
        let d = &self.multilinears[3].packed_evals;

        // compute indices for either high to low or low to high
        let compute_idx: fn((usize, usize)) -> (usize, usize) = match self.fold_direction {
            FoldDirection::LowToHigh => |(j, _)| (2 * j, 2 * j + 1),
            FoldDirection::HighToLow => |(j, n)| (j, n + j),
        };

        // chunk indices into 1024 chunks
        let (mut g_of_zero, mut g_leading_coeff) = (0..n_half)
            .into_par_iter()
            .chunks(1024)
            .map(|chunk| {
                // let _span = tracing::debug_span!("high to low fold inplace parallel").entered();

                let mut acc_g_of_zero = BF::ZERO;
                let mut acc_g_leading_coeff = BF::ZERO;

                for j in chunk {
                    let (low_idx, high_idx) = compute_idx((j, n_half));

                    let a_lower = a[low_idx];
                    let b_lower = b[low_idx];
                    let c_lower = c[low_idx];
                    let d_lower = d[low_idx];

                    let a_upper = a[high_idx];
                    let b_upper = b[high_idx];
                    let d_upper = d[high_idx];

                    acc_g_of_zero += (a_lower * b_lower - c_lower) * d_lower;
                    acc_g_leading_coeff +=
                        (a_lower + a_upper) * (b_lower + b_upper) * (d_lower + d_upper);
                }

                (acc_g_of_zero, acc_g_leading_coeff)
            })
            .reduce(
                || (BF::ZERO, BF::ZERO),
                |(sum0, sum1), (x0, x1)| (sum0 + x0, sum1 + x1),
            );

        // multiply by eq_factor
        g_of_zero *= self.eq_factor;
        g_leading_coeff *= self.eq_factor;

        // g(1) = current_round_claim - g(0)
        let g_of_one = self.current_round_claim - g_of_zero;

        // return round message
        let mut round_msg = Vec::with_capacity(3);
        round_msg.extend([g_of_zero, g_of_one, g_leading_coeff]);
        round_msg
    }

    // parallel fold
    fn fold_par(&mut self, challenge: BF) {
        let _span = tracing::debug_span!("fold inplace parallel").entered();

        let n = 1 << self.multilinears[0].n_vars;
        let n_half = n >> 1;

        match self.fold_direction {
            // Parallel fold safe for high-to-low and low-to-high
            FoldDirection::LowToHigh => {
                self.multilinears
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(i, multilinear)| {
                        // let _span = tracing::debug_span!("low to high fold inplace parallel").entered();

                        if i < 3 {
                            for j in 0..n_half {
                                let (low_idx, high_idx) = (2 * j, 2 * j + 1);
                                let even = multilinear.packed_evals[low_idx];
                                let odd = multilinear.packed_evals[high_idx];
                                multilinear.packed_evals[j] = even + challenge * (odd - even);
                            }
                        } else {
                            for j in 0..n_half {
                                let (low_idx, high_idx) = (2 * j, 2 * j + 1);
                                let even = multilinear.packed_evals[low_idx];
                                let odd = multilinear.packed_evals[high_idx];
                                multilinear.packed_evals[j] = even + odd;
                            }
                        }

                        // remove last 1 << n-1 elements from each multilinear
                        multilinear.packed_evals.truncate(n_half);
                        multilinear.n_vars -= 1;
                    });
            }
            // Parallel fold safe better for high-to-low
            FoldDirection::HighToLow => {
                let [a, b, c, d] = &mut self.multilinears[..] else {
                    panic!("expected 4 multilinears")
                };
                let (a_low, a_high) = a.packed_evals.split_at_mut(n_half);
                let (b_low, b_high) = b.packed_evals.split_at_mut(n_half);
                let (c_low, c_high) = c.packed_evals.split_at_mut(n_half);
                let (d_low, d_high) = d.packed_evals.split_at_mut(n_half);

                for (low, high) in [
                    (a_low, a_high),
                    (b_low, b_high),
                    (c_low, c_high),
                    (d_low, d_high),
                ] {
                    low.par_chunks_mut(1024).for_each(|chunk| {
                        // let _span = tracing::debug_span!("high to low fold inplace parallel").entered();
                        for (elm, high_elm) in chunk.iter_mut().zip(high.iter()) {
                            *elm += challenge * (*high_elm - *elm);
                        }
                    });
                }

                for i in 0..self.multilinears.len() {
                    self.multilinears[i].packed_evals.truncate(n_half);
                    self.multilinears[i].n_vars -= 1;
                }
            }
        }
    }
}

impl SumcheckProver<BF> for MultilinearSumcheckProver {
    // folds challenge into multilinears
    fn fold(&mut self, challenge: BF) {
        self.fold_par(challenge);
        // self.fold_seq(challenge);
    }

    // computes univariate round message for the current round
    fn round_message(&self) -> Vec<BF> {
        self.round_msg_par()
        // self.round_msg_seq()
    }

    fn final_eval_claims(self) -> Vec<BF> {
        self.final_eval_claims
    }
}

// since it could let us abstract concepts like rng from the implementation
fn random_challenge() -> BF {
    let mut rng = StdRng::from_seed([0; 32]);
    BF::random(&mut rng)
}

// given 4 lagrange basis coefficients for a univariate polynomial, compute
// lagrange basis polynomials and evaluate at x the resulting polynomial
fn evaluate_round_polynomial_at(x: BF, zerocheck_challenge: BF, round_msg: Vec<BF>) -> BF {
    let _span = tracing::debug_span!("evaluate round polynomial").entered();

    let (x_0, y_0) = (BF::ZERO, round_msg[0]);
    let (x_1, y_1) = (BF::ONE, round_msg[1]);

    let leading_coeff = round_msg[2];

    // we are only interested in the multilinear composition (A * B - C) * eq_r,
    // we can factor eq_r = eq(x_0, x_1, ..., x_{n-1}, r_0, r_1, ..., r_{n-1})
    // into eq(x_0, r_0) * eq(x_1, .. x_{n-1}, r_1, .. r_{n-1}), of which
    // eq(x_0, r_0) = (1 - x_0)(1 - r_0) + (x_0)(r_0) = 1 - x_0 - r_0 + 2 * (x_0 * r_0)
    // However, because we are in a binary field, 2 * (x_0 * r_0) = 0, so we can simplify to
    // eq(x_0, r_0) = 1 - x_0 - r_0 = x_0 - (r_0 + 1)
    // This reveals to use that there is a root of the polynomial at x = r_0 + 1
    // meaning that the prover does not need to send this value explicitly, rather
    // the verifier can determine this evaluation by inference from the current
    // zerocheck challenge.
    let (x_2, y_2) = (zerocheck_challenge + BF::ONE, BF::ZERO);

    // lagrange basis polynomials
    let l_0 = ((x - x_1) * (x - x_2)) * ((x_0 - x_1) * (x_0 - x_2)).invert().unwrap();
    let l_1 = ((x - x_0) * (x - x_2)) * ((x_1 - x_0) * (x_1 - x_2)).invert().unwrap();
    let l_2 = ((x - x_0) * (x - x_1)) * ((x_2 - x_0) * (x_2 - x_1)).invert().unwrap();

    let vanishing_poly = (x - x_0) * (x - x_1) * (x - x_2);

    l_0 * y_0 + l_1 * y_1 + l_2 * y_2 + vanishing_poly * leading_coeff
}

// verifier checks for correctness of round message and claim
pub fn verify_round(
    round_sum_claim: BF,
    expected_round_claim: BF,
    round_msg: Vec<BF>,
    sumcheck_challenge: BF,
    zerocheck_challenge: BF,
) -> BF {
    let _span = tracing::debug_span!("verify round").entered();

    // first two coefficients of round message should match the sum claim
    // these are the evaluations of the univariate polynomial at 0, 1 and
    // (even/odd sum of boolean hypercube evals)
    assert_eq!(round_msg[0] + round_msg[1], round_sum_claim);

    // When the verifier recieves the round message, it represents the coefficients
    // of the current univariate, partially specialized composition polynomial. By
    // evaluating this polynomial at the challenge, we determine what the honest
    // prover will claim as the sum for the next round. This is because the when
    // we fold the challenge into the multilinear, it is the same as partially
    // specializing the current composition polynomial w/ the challenge point.
    assert_eq!(expected_round_claim, round_sum_claim);

    // compute expected next round claim

    evaluate_round_polynomial_at(sumcheck_challenge, zerocheck_challenge, round_msg)
}

// runs sumcheck interactive protocol for multilinear composition (A * B - C) * eq_r
// eq_r is the multilinear equality indicator for some vector of log_n zerocheck challenges
pub fn multilinear_sumcheck(prover: &mut MultilinearSumcheckProver) -> (BF, Vec<BF>) {
    let _span = tracing::debug_span!("multilinear_sumcheck").entered();
    let log_n = prover.log_n;

    let mut expected_next_round_claim = prover.overall_claim;
    let mut sumcheck_challenges = Vec::with_capacity(log_n);

    for round_idx in 0..log_n {
        let _span = tracing::debug_span!("multilinear sumcheck round").entered();

        let challenge_idx = match prover.fold_direction {
            FoldDirection::LowToHigh => round_idx,
            FoldDirection::HighToLow => log_n - round_idx - 1,
        };

        // verifier sends sumcheck challenge
        let sumcheck_challenge = random_challenge();
        sumcheck_challenges.push(sumcheck_challenge);

        // prover computes round message
        let round_msg = prover.round_message();
        prover.eq_factor *=
            prover.zerocheck_challenges[challenge_idx] + sumcheck_challenge + BF::ONE;

        // verifier checks round message against claim
        expected_next_round_claim = verify_round(
            prover.current_round_claim,
            expected_next_round_claim,
            round_msg.clone(),
            sumcheck_challenge,
            prover.zerocheck_challenges[challenge_idx], // eq_ind expects zerocheck challenges in rev order
        );

        // prover sets next round claim
        prover.current_round_claim = evaluate_round_polynomial_at(
            sumcheck_challenge,
            prover.zerocheck_challenges[challenge_idx],
            round_msg.clone(),
        );

        // prover folds challenge into multilinear
        prover.fold(sumcheck_challenge);

        // prover stores current eval claim for this round
        prover.final_eval_claims.push(prover.current_round_claim);
    }

    (expected_next_round_claim, sumcheck_challenges)
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::and_reduction::mle::mle_to_field_buffer;
    use binius_field::AESTowerField128b;

    // generate multiple random multilinears of log_n variables
    pub fn random_multilinears(
        num_multilinears: usize,
        log_n: usize,
    ) -> Vec<BigFieldMultilinear<BF>> {
        let mut rng = StdRng::from_seed([0; 32]);

        let n = 1 << log_n;
        let mut multilinears = Vec::with_capacity(num_multilinears);
        for _ in 0..num_multilinears {
            let multilinear = BigFieldMultilinear {
                n_vars: log_n,
                packed_evals: (0..n)
                    .map(|_| BF::from(AESTowerField128b::random(&mut rng)))
                    .collect::<Vec<BF>>(),
            };

            multilinears.push(multilinear);
        }

        multilinears
    }

    // runs sumcheck protocol for a 4 column composition polynomial (A * B - C) * eq_r
    // tests both high to low and low to high fold directions
    #[test]
    fn test_sumcheck_four_column() {
        let mut rng = StdRng::from_seed([0; 32]);

        let log_n = 5;
        let num_multilinears = 3;

        // zerocheck challenges (polyval)
        let zerocheck_challenges = (0..log_n)
            .map(|_| BinaryField128bPolyval::from(AESTowerField128b::random(&mut rng)))
            .collect::<Vec<BF>>();

        for fold_direction in [FoldDirection::LowToHigh, FoldDirection::HighToLow] {
            let multilinears: Vec<BigFieldMultilinear<BF>> =
                random_multilinears(num_multilinears, log_n);

            // eq_r is the multilinear equality indicator for some vector of log_n zerocheck challenges
            let eq_r: BigFieldMultilinear<BF> = eq_ind(&zerocheck_challenges.clone());

            // compute overall sum claim for (A * B - C) * eq_r
            let overall_claim = MultilinearSumcheckProver::sum_composition(
                &multilinears[0],
                &multilinears[1],
                &multilinears[2],
                &eq_r,
            );

            // create multilinear sumcheck prover
            let mut prover = MultilinearSumcheckProver::new(
                multilinears,
                zerocheck_challenges.clone(),
                overall_claim,
                log_n,
                fold_direction,
            );

            // run sumcheck
            multilinear_sumcheck(&mut prover);

            // gather final eval claims
            let _final_eval_claims = prover.final_eval_claims();
        }
    }

    #[test]
    fn test_composition_even_odd_sum() {
        let log_n = 5;
        let n = 1 << log_n;

        let num_multilinears = 4;

        let multilinears: Vec<BigFieldMultilinear<BF>> =
            random_multilinears(num_multilinears, log_n);
        let overall_sum = MultilinearSumcheckProver::sum_composition(
            &multilinears[0],
            &multilinears[1],
            &multilinears[2],
            &multilinears[3],
        );

        // produce g(0), g(1) by summing over evals where first var is 0, 1
        let mut g_of_zero = BF::ZERO;
        let mut g_of_one = BF::ZERO;
        for j in 0..n {
            let a = multilinears[0].packed_evals[j];
            let b = multilinears[1].packed_evals[j];
            let c = multilinears[2].packed_evals[j];
            let d = multilinears[3].packed_evals[j];

            if j % 2 == 0 {
                g_of_zero += (a * b - c) * d;
            } else {
                g_of_one += (a * b - c) * d;
            }
        }

        assert_eq!(overall_sum, g_of_zero + g_of_one);
    }
}
