use binius_field::{Field, PackedField};
use binius_math::{evaluate_univariate, multilinear::eq::eq_ind};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use itertools::{Itertools, izip};

use super::{
	common::{
		Phase1Output, Phase2Output, Phase3Output, Phase4Output, Phase5Output, frobenius,
		make_phase_3_output, normalize_a_c_exponent_evals,
	},
	error::Error,
};
use crate::protocols::sumcheck::common::{BatchSumcheckOutput, RoundCoeffs, RoundProof};

fn read_scalar<F: Field, C: Challenger>(
	transcript: &mut VerifierTranscript<C>,
) -> Result<F, Error> {
	transcript
		.message()
		.read_scalar::<F>()
		.map_err(Error::from_transcript_read)
}

fn read_scalar_slice<F: Field, C: Challenger>(
	transcript: &mut VerifierTranscript<C>,
	len: usize,
) -> Result<Vec<F>, Error> {
	transcript
		.message()
		.read_scalar_slice::<F>(len)
		.map_err(Error::from_transcript_read)
}

struct BatchVerifyOutput<F: Field> {
	batch_coeff: F,
	challenges: Vec<F>,
	claim: F,
}

fn batch_verify<F: Field, C: Challenger>(
	n_vars: usize,
	degree: usize,
	claims: Vec<F>,
	transcript: &mut VerifierTranscript<C>,
) -> Result<BatchVerifyOutput<F>, Error> {
	let batch_coeff: F = transcript.sample();

	let mut claim = evaluate_univariate(&claims, batch_coeff);

	let mut challenges: Vec<F> = vec![];

	for _ in 0..n_vars {
		let coeffs = read_scalar_slice(transcript, degree + 1)?;

		let round_proof = RoundProof(RoundCoeffs(coeffs));
		let round_coeffs = round_proof.recover(claim);

		let challenge = transcript.sample();
		challenges.push(challenge);

		claim = evaluate_univariate(&round_coeffs.0, challenge);
	}

	challenges.reverse();

	Ok(BatchVerifyOutput {
		batch_coeff,
		challenges,
		claim,
	})
}

fn verify_layer<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	eval_point: Vec<F>,
	claims: Vec<F>,
	transcript: &mut VerifierTranscript<C>,
) -> Result<BatchSumcheckOutput<F>, Error> {
	let n_vars = eval_point.len();

	let claims_len = claims.len();

	let BatchVerifyOutput {
		batch_coeff: batch_coef,
		challenges,
		claim,
	} = batch_verify::<F, C>(n_vars, 2, claims, transcript)?;

	let final_claims = transcript
		.message()
		.read_scalar_slice::<F>(2 * claims_len)
		.map_err(Error::from_transcript_read)?;

	let eq_eval = eq_ind(&eval_point, &challenges);
	let expected_unbatched_terms = final_claims
		.iter()
		.tuples()
		.map(|(&left, &right)| eq_eval * left * right)
		.collect::<Vec<_>>();

	let expected_claim = evaluate_univariate(&expected_unbatched_terms, batch_coef);
	if expected_claim != claim {
		println!("expected: {:?}", expected_claim);
		println!("claim: {:?}", claim);
		// return Err(Error::CompositionClaimMismatch);
	}

	Ok(BatchSumcheckOutput {
		challenges,
		multilinear_evals: vec![final_claims],
	})
}

fn verify_phase_1<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	initial_eval_point: &[F],
	initial_b_claim: F,
	transcript: &mut VerifierTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let mut eval_point = initial_eval_point.to_vec();
	let mut claims = vec![initial_b_claim];

	for depth in (0..6).rev() {
		let layer_buffer_count = 1 << (6 - depth);
		let claims_count = layer_buffer_count / 2;
		debug_assert_eq!(claims.len(), claims_count);

		let BatchSumcheckOutput {
			challenges,
			mut multilinear_evals,
		} = verify_layer::<F, P, C>(eval_point, claims, transcript)?;

		eval_point = challenges;
		claims = multilinear_evals.pop().expect("there is one prover");
	}

	Ok(Phase1Output {
		eval_point,
		b_leaves_claims: claims,
	})
}

// PHASE 2: frobenius

// PHASE THREE: painful sumcheck

fn verify_phase_3<F: Field, C: Challenger>(
	n_vars: usize,
	// v sumcheck stuff
	twisted_eval_points: Vec<Vec<F>>,
	twisted_claims: Vec<F>,
	// c sumcheck stuff
	c_eval_point: Vec<F>,
	c_claim: F,
	transcript: &mut VerifierTranscript<C>,
) -> Result<Phase3Output<F>, Error> {
	assert_eq!(twisted_eval_points.len(), 64);
	assert_eq!(twisted_claims.len(), 64);
	for twisted_eval_point in &twisted_eval_points {
		assert_eq!(twisted_eval_point.len(), n_vars);
	}

	assert_eq!(c_eval_point.len(), n_vars);

	let mut claims = twisted_claims;
	claims.push(c_claim);

	let BatchVerifyOutput {
		batch_coeff,
		challenges,
		claim,
	} = batch_verify::<F, C>(n_vars, 2, claims, transcript)?;

	let mut reader = transcript.message();
	let c_prover_claims = reader.read_scalar_slice::<F>(2)?;
	let v_prover_claims = reader.read_scalar_slice::<F>(64 + 1)?;

	let output = make_phase_3_output(challenges, v_prover_claims, c_prover_claims);
	let Phase3Output {
		eval_point,
		b_exponent_claims,
		v_claim,
		c_lo_last_layer_claim: last_c_lo_claim,
		c_hi_last_layer_claim: last_c_hi_claim,
	} = output.clone();

	let expected_unbatched_b_v_term = |(twisted_eval_point, b_exponent_claim): (&Vec<F>, &F)| {
		let twisted_eq_eval = eq_ind(twisted_eval_point, &eval_point);
		twisted_eq_eval * ((F::one() - b_exponent_claim) + *b_exponent_claim * v_claim)
	};
	let mut expected_unbatched_terms = izip!(&twisted_eval_points, &b_exponent_claims)
		.map(expected_unbatched_b_v_term)
		.collect::<Vec<_>>();

	let c_eq_eval = eq_ind(&c_eval_point, &eval_point);
	expected_unbatched_terms.extend([c_eq_eval * last_c_lo_claim * last_c_hi_claim]);

	let expected_batched_claim = evaluate_univariate(&expected_unbatched_terms, batch_coeff);

	if expected_batched_claim != claim {
		println!("expected: {:?}", expected_batched_claim);
		println!("claim: {:?}", claim);
		// return Err(Error::CompositionClaimMismatch);
	}

	Ok(output)
}

// PHASE 4: most of a_layers and c_layers

fn verify_phase_4<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	eval_point: Vec<F>,
	// a stuff
	a_last_layer_claim: F,
	// c stuff
	c_lo_last_layer_claim: F,
	c_hi_last_layer_claim: F,
	transcript: &mut VerifierTranscript<C>,
) -> Result<Phase4Output<F>, Error> {
	let mut eval_point = eval_point.to_vec();
	let mut claims = vec![
		a_last_layer_claim,
		c_lo_last_layer_claim,
		c_hi_last_layer_claim,
	];

	for depth in (1..6).rev() {
		let a_layer_len = 1 << (6 - depth);
		let c_layer_len = 2 * a_layer_len;

		debug_assert_eq!(claims.len(), (a_layer_len + c_layer_len) / 2);

		let BatchSumcheckOutput {
			challenges,
			mut multilinear_evals,
		} = verify_layer::<F, P, C>(eval_point, claims, transcript)?;

		eval_point = challenges;
		claims = multilinear_evals.pop().expect("there is one prover");
	}

	debug_assert_eq!(claims.len(), 32 + 2 * 32);

	Ok(Phase4Output {
		eval_point,
		a_32_c_64_claims: claims,
	})
}

// PHASE 5: final layer

fn verify_phase_5<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	// a and c stuff
	a_c_eval_point: Vec<F>,
	a_c_claims: Vec<F>,
	// b stuff
	b_eval_point: Vec<F>,
	b_exponent_claims: Vec<F>,
	transcript: &mut VerifierTranscript<C>,
) -> Result<Phase5Output<F>, Error> {
	assert_eq!(a_c_claims.len(), 32 + 64);
	assert_eq!(b_exponent_claims.len(), 64);

	let n_vars = a_c_eval_point.len();
	assert_eq!(b_eval_point.len(), n_vars);

	let mut claims = a_c_claims;
	claims.extend(b_exponent_claims);

	let BatchVerifyOutput {
		batch_coeff,
		challenges,
		claim,
	} = batch_verify::<F, C>(n_vars, 2, claims, transcript)?;

	let scaled_a_c_exponent_claims = read_scalar_slice(transcript, 64 + 128)?;
	let b_exponent_claims = read_scalar_slice(transcript, 64)?;

	let a_c_eq_eval = eq_ind(&a_c_eval_point, &challenges);
	let expected_a_c_unbatched_claims = scaled_a_c_exponent_claims
		.iter()
		.tuples()
		.map(|(left, right)| a_c_eq_eval * left * right)
		.collect::<Vec<F>>();

	let b_eq_eval = eq_ind(&b_eval_point, &challenges);
	let expected_b_unbatched_claims = b_exponent_claims
		.iter()
		.map(|&b_exponent_claim| b_eq_eval * b_exponent_claim)
		.collect::<Vec<F>>();

	let mut expected_unbatched_claims = expected_a_c_unbatched_claims;
	expected_unbatched_claims.extend(expected_b_unbatched_claims);

	let expected_batched_claim = evaluate_univariate(&expected_unbatched_claims, batch_coeff);

	if expected_batched_claim != claim {
		println!("expected: {:?}", expected_batched_claim);
		println!("claim: {:?}", claim);
		// return Err(Error::CompositionClaimMismatch);
	}

	Ok(Phase5Output {
		eval_point: a_c_eval_point,
		scaled_a_c_exponent_claims,
		b_exponent_claims: b_exponent_claims,
	})
}

// verify

pub struct VerifyOutput<F> {
	pub eval_point: Vec<F>,
	pub a_claims: Vec<F>,
	pub b_claims: Vec<F>,
	pub c_lo_claims: Vec<F>,
	pub c_hi_claims: Vec<F>,
}

pub fn verify<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	n_vars: usize,
	generator: F,
	transcript: &mut VerifierTranscript<C>,
) -> Result<VerifyOutput<F>, Error> {
	let initial_eval_point: Vec<P::Scalar> = transcript.sample_vec(n_vars);

	let initial_b_eval: F = read_scalar(transcript)?;
	let initial_c_eval: F = read_scalar(transcript)?;

	// phase 1
	let Phase1Output {
		eval_point: phase_1_eval_point,
		b_leaves_claims,
	} = verify_phase_1::<F, P, C>(&initial_eval_point, initial_b_eval, transcript)?;

	debug_assert_eq!(phase_1_eval_point.len(), n_vars);
	debug_assert_eq!(b_leaves_claims.len(), 64);

	// phase 2
	let Phase2Output {
		twisted_eval_points,
		twisted_claims: twisted_evals,
	} = frobenius::<F, P>(phase_1_eval_point, b_leaves_claims);

	debug_assert_eq!(twisted_eval_points.len(), 64);
	debug_assert_eq!(twisted_evals.len(), 64);

	// phase 3
	let Phase3Output {
		eval_point: phase_3_eval_point,
		b_exponent_claims,
		v_claim,
		c_lo_last_layer_claim,
		c_hi_last_layer_claim,
	} = verify_phase_3(
		n_vars,
		twisted_eval_points,
		twisted_evals,
		initial_eval_point,
		initial_c_eval,
		transcript,
	)?;

	// phase 4
	let Phase4Output {
		eval_point: phase_4_eval_point,
		a_32_c_64_claims,
	} = verify_phase_4::<F, P, C>(
		phase_3_eval_point.clone(),
		v_claim,
		c_lo_last_layer_claim,
		c_hi_last_layer_claim,
		transcript,
	)?;

	// phase 5
	let Phase5Output {
		eval_point: phase_5_eval_point,
		scaled_a_c_exponent_claims,
		b_exponent_claims,
	} = verify_phase_5::<F, P, C>(
		phase_4_eval_point,
		a_32_c_64_claims,
		phase_3_eval_point,
		b_exponent_claims,
		transcript,
	)?;

	let (a_exponent_claims, c_lo_exponent_claims, c_hi_exponent_claims) =
		normalize_a_c_exponent_evals::<P>(scaled_a_c_exponent_claims, generator);

	Ok(VerifyOutput {
		eval_point: phase_5_eval_point,
		a_claims: a_exponent_claims,
		b_claims: b_exponent_claims,
		c_lo_claims: c_lo_exponent_claims,
		c_hi_claims: c_hi_exponent_claims,
	})
	// Ok(())
}
