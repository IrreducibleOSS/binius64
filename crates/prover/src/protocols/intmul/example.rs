use binius_field::{BinaryField128b, Field, PackedBinaryField1x128b, PackedField};
use binius_math::{evaluate_univariate, field_buffer::FieldBuffer, multilinear::eq::eq_ind};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use blake2::Blake2b;
use digest::consts::U32;

use super::prove::compute_eval;
type F = BinaryField128b;
type P = PackedBinaryField1x128b;
use itertools::izip;

use crate::protocols::sumcheck::{
	common::SumcheckProver,
	selector_mle::{Claim, SelectorMlecheckProver},
};

fn example<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	eval_point: Vec<F>,
	v_buffer: FieldBuffer<P>,
	exponents: &[u64],
	transcript: &mut ProverTranscript<C>,
) {
	assert_eq!(eval_point.len(), v_buffer.log_len());

	let multilinear = make_multilinear::<P>(0, &exponents, &v_buffer);

	let eval = compute_eval(&eval_point, multilinear.clone());

	let claims = vec![Claim {
		point: eval_point.clone(),
		value: eval,
	}];

	let mut v_prover = SelectorMlecheckProver::new(v_buffer.clone(), claims, exponents, 0).unwrap();

	let mut claim = eval;

	let mut challenges = Vec::with_capacity(v_buffer.log_len());
	for _ in 0..v_buffer.log_len() {
		let round_coeffs_vec = v_prover.execute().unwrap();
		assert_eq!(round_coeffs_vec.len(), 1);
		let round_coeffs = round_coeffs_vec[0].clone();

		let challenge = transcript.sample();
		challenges.push(challenge);

		claim = evaluate_univariate(&round_coeffs.0, challenge);

		v_prover.fold(challenge).unwrap();
	}

	challenges.reverse();

	let multilinear_evals = v_prover.finish().unwrap();
	assert_eq!(multilinear_evals.len(), 2);

	assert_eq!(multilinear_evals[1], compute_eval(&challenges, v_buffer.clone()));
	println!("multilinear_evals: {:#?}", multilinear_evals);

	let expected_thing =
		eq_ind(&eval_point, &challenges) * multilinear_evals[0] * multilinear_evals[1];

	assert_eq!(claim, expected_thing);

	println!("WORKED!");
	assert!(false);
}

fn make_multilinear<P: PackedField>(
	k: usize,
	exponents: &[u64],
	v_buffer: &FieldBuffer<P>,
) -> FieldBuffer<P> {
	let mut dest = FieldBuffer::<P>::zeros(v_buffer.log_len());

	for (v, exponents, dest) in izip!(v_buffer.as_ref(), exponents.chunks(P::WIDTH), dest.as_mut())
	{
		let scalars = P::iter(v).zip(exponents).map(|(b, e)| {
			if e & (1 << k) == 0 {
				P::Scalar::ZERO
			} else {
				b
			}
		});
		*dest = P::from_scalars(scalars);
	}

	dest
}

// #[test]
// fn example() {
// 	let mut transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::default();

// 	let log_len = 3;

// 	let mut rng = rand::rng();

// 	let mut buffer_0 = FieldBuffer::<P>::zeros(log_len);
// 	let mut buffer_1 = FieldBuffer::<P>::zeros(log_len);

// 	let slice_0 = buffer_0.as_mut();
// 	let slice_1 = buffer_1.as_mut();

// 	let packed_length = 1 << log_len.saturating_sub(P::LOG_WIDTH);
// 	for i in 0..packed_length {
// 		let random_f0: Vec<F> = (0..P::WIDTH).map(|_| F::random(&mut rng)).collect();
// 		let random_f1: Vec<F> = (0..P::WIDTH).map(|_| F::random(&mut rng)).collect();
// 		// let random_f0: Vec<F> = (0..P::WIDTH).map(|_| F::one()).collect();
// 		// let random_f1: Vec<F> = (0..P::WIDTH).map(|_| F::one()).collect();

// 		slice_0[i] = P::from_scalars(random_f0);
// 		slice_1[i] = P::from_scalars(random_f1);
// 	}

// 	// println!("buffer_0: {:#?}", buffer_0);
// 	// println!("buffer_1: {:#?}", buffer_1);

// 	let eval_point = transcript.sample_vec(log_len);

// 	let product = compute_bivariate_product(buffer_0.to_ref(), buffer_1.to_ref()).unwrap();
// 	// println!("product: {:#?}", product);

// 	let (eval, _) = compute_initial_evals(&eval_point, product.clone(), product).unwrap();
// 	// println!("eval: {:#?}", eval);

// 	prove_layer_test(buffer_0, buffer_1, &eval_point, eval, &mut transcript);
// }

// fn prove_layer_test<'a, F: Field, P: PackedField<Scalar = F>, C: Challenger>(
// 	buffer_0: FieldBuffer<P>,
// 	buffer_1: FieldBuffer<P>,
// 	eval_point: &[F],
// 	mut claim: F,
// 	transcript: &mut ProverTranscript<C>,
// ) {
// 	assert_eq!(buffer_0.log_len(), eval_point.len());
// 	assert_eq!(buffer_1.log_len(), eval_point.len());

// 	let layer = vec![(buffer_0, buffer_1)];
// 	let claims = vec![claim];
// 	let mut prover = BivariateMlecheckProver::new(layer, &eval_point, &claims).unwrap();

// 	let mut challenges: Vec<F> = vec![];

// 	for _ in 0..eval_point.len() {
// 		let round_coeffs_vec = prover.execute().unwrap();
// 		assert_eq!(round_coeffs_vec.len(), 1);
// 		let round_coeffs = &round_coeffs_vec[0];

// 		let challenge = transcript.sample();
// 		challenges.push(challenge);

// 		claim = evaluate_univariate(&round_coeffs.0, challenge);

// 		prover.fold(challenge).unwrap();
// 	}

// 	let final_claims: Vec<F> = prover.finish().unwrap();
// 	assert_eq!(final_claims.len(), 2);

// 	challenges.reverse();

// 	let eq_eval = eq_ind(&eval_point, &challenges);
// 	let expected_claim = eq_eval * final_claims[0] * final_claims[1];

// 	println!("expected_claim: {:#?}", expected_claim);
// 	println!("claim: {:#?}", claim);

// 	assert_eq!(expected_claim, claim);
// }
