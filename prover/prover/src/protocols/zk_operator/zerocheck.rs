//!
//! For ZK we want the prover's messages uniformly distributed.
//! If the prover's messages are an affine function of the prover's randomness, and we can prove that the affine map is surjective (has rank equal to the output dimension), then we can rest assured that if the inputs are uniformly distributed then the outputs are also uniformly distributed.
//! Imagine a fixed witness and fixed verifier challenges. Then we can construct a map from the prover's randomness to the prover's messages. We can prove this map to be affine via a probabilistic test with negligible error (see in the code below). We can also prove the map to be surjective, ie the map has rank m where m is the output dimension, by passing at least m random inputs through the map and checking the outputs to be linearly independent.
//! That is the experiment performed in this module. There are no zerocheck challenges right now for simplicity, but those will not affect the purpose of this experiment.
//! In this experiment we show that if the prover chooses 2*n_vars random inputs and inserts them carefully into dummy constraints, then we can reduce to linear constraints with only 2*n_vars prover messages, and our mapping moreover satisfies affinity and surjectivity. Thus we have a ZK zerocheck. It took many iterations to design this affine function.
//!
//! Now of course the witness is not fixed and neither are the verifier's challenges.
//! But for a moment continue to suppose the prover holds a fixed witness.
//! Suppose the prover chooses a single set of challenges to parameterize our affine function, and suppose the prover confirms the resulting map is indeed surjective.
//! Then the prover can rest assured the map will be surjective for the vast majority of verifier challenges, and thus the prover can be confident of ZK.
//! I'll explain why now:
//! In the case of this experiment, the input and output sizes coincide so the matrix is square, and we're actually proving invertibility, not just surjectivity.
//! In the case of square matrices we have invertibility if and only if the determinant is non-zero. The verifier challenges are variables that show up in the expressions making up the entries of this matrix. Suppose each entry is an expression of degree at most d in the verifier challenges. Indeed, analyzing the proof system this can be easily confirmed, and d is usually logarithmic in the witness size. Then the degree of the verifier's challenges in the determinant of the nxn matrix is at most n*d. By the Schwartz-Zippel lemma, we can conclude that if the determinant is not identically zero then whp over the verifier's challenges the map will remain invertible.
//! By confirming the map to be invertible for at least one set of verifier challenges as supposed above, the prover confirms the determinant is not identically zero. Of course the prover having to do this extra work for each witness is inconvenient. That's the drawback. To avoid this extra prover work we must resort to analytical math, and I won't get into that here. In fact, I don't even have an analytical proof the map is invertible.
//!
//! I have an analytical proof of a similar ZK sumcheck when multiplying a witness by a transparent, but in this zerocheck experiment we have non-linear constraints, so analytically proving the map invertible is more difficult. The reason is that in the case of linear constraints the proof can proceed round by round, and complexity is contained. But in the case of non-linear constraints, the fact that dummy constraints must satisfy non-linear relations breaks this simplicity. Someone like Ben needs to prove inversion.
//!
//! I've also been building a similar model to prove a ZK FRI-Basefold construction secure. Pair that with this ZK zerocheck and we have a simple and efficient ZK Spartan construction.
//!

use super::algebra::{compute_matrix_rank_from_cols, test_affinity};
use super::polys::*;
use binius_field::{BinaryField128bGhash as Ghash, Field, Random};
use itertools::izip;
use rand::{SeedableRng, rngs::StdRng};

fn run_zerocheck_prover(
	mut f: MultilinearPoly,
	mut g: MultilinearPoly,
	mut h: MultilinearPoly,
) -> (Vec<Ghash>, Vec<Ghash>) {
	let mut rng = StdRng::seed_from_u64(0);
	let n_vars = f.num_vars();

	let original_f = f.clone();
	let original_g = g.clone();
	let original_h = h.clone();

	let mut sum = Ghash::ZERO;
	let mut messages = Vec::new();
	let mut round_challenges = Vec::new();

	for i in 0..n_vars {
		let (f0, f1) = f.split();
		let (g0, g1) = g.split();
		let (h0, h1) = h.split();
		// Coeffs are evals at 0,1,infinity. We'll send the verifier evals at 1 and infinity
		// Can change this to use monomial basis as in Binius64 sumchecks
		let coeffs = compute_round_coeffs(&f0, &f1, &g0, &g1, &h0, &h1);
		assert_eq!(sum, coeffs[0] + coeffs[1]);
		if i == 0 {
			assert_eq!(coeffs[1], Ghash::ZERO);
		} else {
			messages.push(coeffs[1]);
		}
		messages.push(coeffs[2]);

		let challenge = Ghash::random(&mut rng);
		round_challenges.push(challenge);

		f = MultilinearPoly::fold(&f0, &f1, challenge);
		g = MultilinearPoly::fold(&g0, &g1, challenge);
		h = MultilinearPoly::fold(&h0, &h1, challenge);

		sum = evaluate_univariate(&coeffs, challenge);
		assert_eq!(sum, dot_product_sum(&f, &g) - h.sum());
	}

	// Reverse challenges because we fold high to low
	let mut low_to_high_challenges = round_challenges.clone();
	low_to_high_challenges.reverse();

	let f_eval = original_f.evaluate_at(&low_to_high_challenges);
	let g_eval = original_g.evaluate_at(&low_to_high_challenges);
	let h_eval = original_h.evaluate_at(&low_to_high_challenges);
	assert_eq!(f_eval * g_eval - h_eval, sum);

	// The verifier only needs eval of f, not g or h.
	// See how verifier completes verification.
	messages.push(f_eval);

	(messages, round_challenges)
}

fn compute_round_coeffs(
	f0: &MultilinearPoly,
	f1: &MultilinearPoly,
	g0: &MultilinearPoly,
	g1: &MultilinearPoly,
	h0: &MultilinearPoly,
	h1: &MultilinearPoly,
) -> [Ghash; 3] {
	let eval_0 = dot_product_sum(&f0, &g0) - h0.sum();

	let fsum = MultilinearPoly::add(&f0, &f1);
	let gsum = MultilinearPoly::add(&g0, &g1);
	let eval_inf = dot_product_sum(&fsum, &gsum);

	let eval_1 = dot_product_sum(&f1, &g1) - h1.sum();

	[eval_0, eval_1, eval_inf]
}

fn run_zerocheck_verifier(
	messages: &[Ghash],
	challenges: Vec<Ghash>,
	// In practice evaluating these will be delegated to the prover in a PCS
	f: &MultilinearPoly,
	g: &MultilinearPoly,
	h: &MultilinearPoly,
) {
	assert_eq!(messages.len(), 1 + (challenges.len() - 1) * 2 + 1);

	// First round: enforce zero at `0` and `1` (thus enforcing all constraints satisfy),
	// only receiving from the prover eval at `∞`
	let mut sum = evaluate_univariate(&[Ghash::ZERO, Ghash::ZERO, messages[0]], challenges[0]);
	let round_messages = &messages[1..messages.len() - 1];

	// Subsequent rounds: check univariate consistency `p(r) = eval_0 + r*(eval_1 - eval_0) + r²*terms`
	for (chunk, challenge) in izip!(round_messages.chunks(2), challenges.iter().skip(1)) {
		let eval_1 = chunk[0];
		let eval_infty = chunk[1];

		let eval_0 = sum - eval_1;
		sum = evaluate_univariate(&[eval_0, eval_1, eval_infty], *challenge);
	}

	// Challenge reversal: prover folds variables from high to low (`n-1, n-2, ..., 0`)
	// but evaluation expects challenges in low to high order (`0, 1, ..., n-1`)
	let mut low_to_high_challenges = challenges;
	low_to_high_challenges.reverse();

	// The verifier is only given a claimed evaluation of `f`, not `g` or `h`.
	// First it can check this claim to be correct
	let claimed_f_eval = messages[messages.len() - 1];
	let f_eval = f.evaluate_at(&low_to_high_challenges);
	assert_eq!(f_eval, claimed_f_eval);

	// Without holding evals of `g` and `h` the verifier cannot take the classic approach
	// of evaluating both and then checking `f_eval * g_eval - h_eval = sum`
	// Instead, the verifier will check that the multilinear `claimed_f_eval * g - h`
	// evaluated at `low_to_high_challenges` equals `sum`.
	// (We use addition in place of subtraction below, equivalent in binary fields)
	let g_h_poly = MultilinearPoly::add(&MultilinearPoly::scale(g, claimed_f_eval), h);
	let g_h_eval = g_h_poly.evaluate_at(&low_to_high_challenges);
	assert_eq!(g_h_eval, sum);
}

fn compute_zerocheck_affine_map(inputs: &[Ghash], n_vars: usize) -> Vec<Ghash> {
	assert_eq!(inputs.len(), 2 * n_vars);

	let mut f = MultilinearPoly::random(n_vars, 10);
	f.randomize_blocks_at_powers_of_two(&inputs);

	let g = MultilinearPoly::random(n_vars, 11);
	let h = MultilinearPoly::mul(&f, &g);

	// Run the full zerocheck protocol
	let (messages, challenges) = run_zerocheck_prover(f.clone(), g.clone(), h.clone());
	assert_eq!(messages.len(), 2 * n_vars);
	assert_eq!(challenges.len(), n_vars);

	// Verify protocol correctness (sanity check)
	run_zerocheck_verifier(&messages, challenges, &f, &g, &h);

	messages
}

#[test]
fn test_zk_zerocheck() {
	let rng = &mut StdRng::seed_from_u64(12);
	let n_vars = 12;
	let dimension = 2 * n_vars;

	// Generic affine check using closure around compute_affine_map
	test_affinity::<Ghash, _>(rng, dimension, |x: &[Ghash]| {
		compute_zerocheck_affine_map(x, n_vars)
	});

	let mut columns = Vec::new();
	// One extra sample to reduce probability that the map is truly full rank but all outputs land in a subspace
	for _ in 0..dimension + 1 {
		// Happens that input and output sizes coincide, so really we're proving invertibility (not just surjectivity)
		// Inputs are the prover's randomness.
		let inputs: Vec<Ghash> = (0..dimension).map(|_| Ghash::random(&mut *rng)).collect();
		// Outputs are the prover's messages.
		let outputs = compute_zerocheck_affine_map(&inputs, n_vars);

		assert_eq!(outputs.len(), dimension);
		columns.push(outputs);
	}

	let rank = compute_matrix_rank_from_cols::<Ghash>(&columns);

	assert_eq!(rank, dimension);
}
