use binius_field::{Field, PackedField};
use binius_math::{evaluate_univariate, multilinear::eq::eq_ind};
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use itertools::{Itertools, izip};

use super::{
	common::{
		HandleLayerOutput, Phase1Output, Phase2Output, Phase3Output, Phase4Output, Phase5Output,
		frobenius, normalize_a_c_exponent_evals,
	},
	error::Error,
};
use crate::protocols::sumcheck::common::{RoundCoeffs, RoundProof};

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

fn verify_layer<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	eval_point: Vec<F>,
	claims: Vec<F>,
	transcript: &mut VerifierTranscript<C>,
) -> Result<HandleLayerOutput<F>, Error> {
	let n_vars = eval_point.len();

	let batch_coef: F = transcript.sample();
	let mut challenges: Vec<F> = vec![];

	let mut claim = evaluate_univariate(&claims, batch_coef);

	for _ in 0..n_vars {
		let coeffs = read_scalar_slice(transcript, 3)?;

		let round_proof = RoundProof(RoundCoeffs(coeffs));
		let round_coeffs = round_proof.recover(claim);

		let challenge = transcript.sample();
		challenges.push(challenge);

		claim = evaluate_univariate(&round_coeffs.0, challenge);
	}

	challenges.reverse();

	let final_claims = transcript
		.message()
		.read_scalar_slice::<F>(2 * claims.len())
		.map_err(Error::from_transcript_read)?;

	let eq_eval = eq_ind(&eval_point, &challenges);
	let expected_unbatched_terms = final_claims
		.iter()
		.tuples()
		.map(|(&left, &right)| eq_eval * left * right)
		.collect::<Vec<_>>();

	let expected_claim = evaluate_univariate(&expected_unbatched_terms, batch_coef);
	assert_eq!(expected_claim, claim);
	if expected_claim != claim {
		return Err(Error::CompositionClaimMismatch);
	}

	Ok(HandleLayerOutput {
		eval_point: challenges,
		claims: final_claims,
	})
}

fn verify_phase_1<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	initial_eval_point: &[F],
	initial_b_claim: F,
	transcript: &mut VerifierTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let mut eval_point = initial_eval_point.to_vec();
	let mut claims = vec![initial_b_claim];

	for layer_num in (0..6).rev() {
		let depth = 5 - layer_num;
		debug_assert_eq!(claims.len(), 1 << depth);

		let HandleLayerOutput {
			eval_point: new_eval_point,
			claims: new_claims,
		} = verify_layer::<F, P, C>(eval_point, claims, transcript)?;

		eval_point = new_eval_point;
		claims = new_claims;
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
	if twisted_eval_points.len() != 64 {
		return Err(Error::LengthMismatch(twisted_eval_points.len(), 64));
	}

	if twisted_claims.len() != twisted_eval_points.len() {
		return Err(Error::TwistedPointsEvalsMismatch(
			twisted_claims.len(),
			twisted_eval_points.len(),
		));
	}

	for twisted_eval_point in &twisted_eval_points {
		if twisted_eval_point.len() != n_vars {
			return Err(Error::EvalPointBufferLengthMismatch);
		}
	}

	if c_eval_point.len() != n_vars {
		return Err(Error::EvalPointBufferLengthMismatch);
	}

	let batch_coeff: F = transcript.sample();
	let mut challenges = vec![];

	let mut unbatched_claims = twisted_claims;
	unbatched_claims.push(c_claim);
	let mut claim = evaluate_univariate(&unbatched_claims, batch_coeff);

	for _ in 0..n_vars {
		let coeffs = read_scalar_slice(transcript, 3)?;
		let round_proof = RoundProof(RoundCoeffs(coeffs));
		let round_coeffs = round_proof.recover(claim);

		let challenge = transcript.sample();
		challenges.push(challenge);

		claim = evaluate_univariate(&round_coeffs.0, batch_coeff);
	}

	let b_exponent_claims = read_scalar_slice(transcript, 64)?;
	let v_claim = read_scalar(transcript)?;
	let c_lo_claim = read_scalar(transcript)?;
	let c_hi_claim = read_scalar(transcript)?;

	let expected_unbatched_b_v_term = |(twisted_eval_point, b_exponent_claim): (&Vec<F>, &F)| {
		let twisted_eq_eval = eq_ind(twisted_eval_point, &challenges);
		twisted_eq_eval * ((F::one() - b_exponent_claim) + *b_exponent_claim * v_claim)
	};
	let mut expected_unbatched_terms = izip!(&twisted_eval_points, &b_exponent_claims)
		.map(expected_unbatched_b_v_term)
		.collect::<Vec<_>>();

	let c_eq_eval = eq_ind(&c_eval_point, &challenges);
	expected_unbatched_terms.extend([c_eq_eval * c_lo_claim, c_eq_eval * c_hi_claim]);

	let expected_batched_claim = evaluate_univariate(&expected_unbatched_terms, batch_coeff);

	if expected_batched_claim != claim {
		return Err(Error::CompositionClaimMismatch);
	}

	Ok(Phase3Output {
		eval_point: challenges,
		b_exponent_claims,
		v_claim,
		c_claims: (c_lo_claim, c_hi_claim),
	})
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

	for layer_num in (1..6).rev() {
		let depth = 6 - layer_num;
		debug_assert_eq!(claims.len(), 3 * (1 << depth) / 2);

		let HandleLayerOutput {
			eval_point: new_eval_point,
			claims: new_claims,
		} = verify_layer::<F, P, C>(eval_point, claims, transcript)?;

		eval_point = new_eval_point;
		claims = new_claims;
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
	if a_c_claims.len() != 32 + 64 {
		return Err(Error::LengthMismatch(a_c_claims.len(), 32 + 64));
	}
	if b_exponent_claims.len() != 64 {
		return Err(Error::LengthMismatch(b_exponent_claims.len(), 64));
	}

	if a_c_eval_point.len() != b_eval_point.len() {
		return Err(Error::LengthMismatch(a_c_eval_point.len(), b_eval_point.len()));
	}

	let batch_coeff: F = transcript.sample();

	let mut unbatched_claims = a_c_claims;
	unbatched_claims.extend(b_exponent_claims);
	let mut claim = evaluate_univariate(&unbatched_claims, batch_coeff);

	let mut challenges: Vec<F> = vec![];

	for _ in 0..a_c_eval_point.len() {
		let coeffs = read_scalar_slice(transcript, 3)?;
		let round_proof = RoundProof(RoundCoeffs(coeffs));
		let round_coeffs = round_proof.recover(claim);

		let challenge = transcript.sample();
		challenges.push(challenge);

		claim = evaluate_univariate(&round_coeffs.0, challenge);
	}

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
		return Err(Error::CompositionClaimMismatch);
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

	let initial_b_eval = read_scalar(transcript)?;
	let initial_c_eval = read_scalar(transcript)?;

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
		v_claim: a_last_layer_claim,
		c_claims,
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
		a_last_layer_claim,
		c_claims.0,
		c_claims.1,
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
}
