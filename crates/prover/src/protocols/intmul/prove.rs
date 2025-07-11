use binius_field::{Field, PackedField};
use binius_math::{
	evaluate_univariate,
	field_buffer::FieldBuffer,
	multilinear::eq::{eq_ind, eq_ind_partial_eval},
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::{
	intmul::common::{
		HandleLayerOutput, Phase1Output, Phase2Output, Phase3Output, Phase4Output, Phase5Output,
		frobenius, normalize_a_c_exponent_evals,
	},
	sumcheck::common::RoundCoeffs,
};
use itertools::{Itertools, izip};

use super::{
	error::Error,
	execute::Layers,
	provers::{RerandomizationProver, VProver},
};
use crate::protocols::sumcheck::{
	bivariate_mle::BivariateMlecheckProver, common::SumcheckProver,
	rerand_mle::RerandMlecheckProver,
};

fn make_pairs<T>(layer: Vec<T>) -> Vec<(T, T)> {
	layer.into_iter().tuples().collect()
}

pub fn compute_initial_evals<F: Field, P: PackedField<Scalar = F>>(
	eval_point: &[F],
	last_b_buffer: FieldBuffer<P>,
	last_c_buffer: FieldBuffer<P>,
) -> Result<(F, F), Error> {
	if eval_point.len() != last_b_buffer.log_len() || eval_point.len() != last_c_buffer.log_len() {
		return Err(Error::EvalPointBufferLengthMismatch);
	}

	let eq_expansion = eq_ind_partial_eval::<P>(eval_point);

	fn compute_eval<F: Field, P: PackedField<Scalar = F>>(
		eq_expansion: &FieldBuffer<P>,
		buffer: FieldBuffer<P>,
	) -> F {
		let packed_eval: P = izip!(eq_expansion.as_ref(), buffer.as_ref())
			.fold(P::default(), |acc, (&eq, &buf)| acc + eq * buf);
		packed_eval.iter().sum()
	}

	let b_eval = compute_eval(&eq_expansion, last_b_buffer);
	let c_eval = compute_eval(&eq_expansion, last_c_buffer);

	Ok((b_eval, c_eval))
}

fn prove_layer<'a, F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	layer: Vec<FieldBuffer<P>>,
	eval_point: Vec<F>,
	claims: Vec<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<HandleLayerOutput<F>, Error> {
	let pairs_count = layer.len() / 2;
	let n_vars = eval_point.len();

	if pairs_count != claims.len() {
		return Err(Error::LayerPairsCountClaimsMismatch(pairs_count, claims.len()));
	}

	for buffer in &layer {
		if buffer.log_len() != n_vars {
			return Err(Error::BufferEvalPointMismatch(buffer.log_len(), n_vars));
		}
	}

	let mut prover = BivariateMlecheckProver::new(make_pairs(layer), &eval_point, &claims)
		.expect("checked input metrics");

	let batch_coeff: F = transcript.sample();
	let mut challenges: Vec<F> = vec![];

	let mut claim = evaluate_univariate(&claims, batch_coeff);

	let mut claim = claims
		.iter()
		.rfold(F::ZERO, |eval, &coeff| eval * batch_coeff + coeff);

	for _ in 0..n_vars {
		let round_coeffs_vec = prover.execute().map_err(Error::from_sumcheck_execute)?;
		if round_coeffs_vec.len() != pairs_count {
			return Err(Error::RoundCoeffsPairsMismatch(round_coeffs_vec.len(), pairs_count));
		}

		let batched_round_coeffs: RoundCoeffs<F> = round_coeffs_vec
			.iter()
			// .fold(RoundCoeffs::default(), |acc, round_coeffs| acc + round_coeffs);
			// .rev()
			.rfold(RoundCoeffs::default(), |acc, round_coeffs| acc * batch_coeff + round_coeffs);

		let challenge = transcript.sample();
		challenges.push(challenge);

		claim = evaluate_univariate(&batched_round_coeffs.0, challenge);

		let round_proof = batched_round_coeffs.truncate();
		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		prover.fold(challenge).map_err(Error::from_sumcheck_fold)?;
	}

	let final_claims = prover.finish().map_err(Error::from_sumcheck_finish)?;
	if final_claims.len() != 2 * pairs_count {
		return Err(Error::FinalClaimsPairsMismatch(final_claims.len(), 2 * pairs_count));
	}

	challenges.reverse();

	let eq_eval = eq_ind(&eval_point, &challenges);
	let expected_unbatched_terms = final_claims
		.iter()
		.tuples()
		.map(|(&left, &right)| eq_eval * left * right)
		.collect::<Vec<_>>();

	let expected_claim: F = evaluate_univariate(&expected_unbatched_terms, batch_coeff);
	assert_eq!(expected_claim, claim);
	if expected_claim != claim {
		return Err(Error::CompositionClaimMismatch);
	}

	transcript.message().write_scalar_slice(&final_claims);

	Ok(HandleLayerOutput {
		eval_point: challenges,
		claims: final_claims,
	})
}

// PHASE ONE: b_layers

fn prove_phase_1<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	mut b_layers: Layers<P>,
	initial_eval_point: Vec<F>,
	initial_claim: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let mut eval_point = initial_eval_point;
	let mut claims = vec![initial_claim];

	for depth in (0..6).rev() {
		let layer_buffer_count = 1 << (6 - depth);
		let claims_count = layer_buffer_count / 2;
		if claims.len() != claims_count {
			return Err(Error::LengthMismatch(claims.len(), claims_count));
		}

		let layer = b_layers.next().expect("taking layer layer_num >= 0");
		if layer.len() != layer_buffer_count {
			return Err(Error::LayerClaimsMismatch(layer.len(), layer_buffer_count));
		}

		let HandleLayerOutput {
			eval_point: new_eval_point,
			claims: new_claims,
		} = prove_layer(layer, eval_point, claims, transcript)?;

		eval_point = new_eval_point;
		claims = new_claims;
	}

	debug_assert_eq!(claims.len(), 64);

	debug_assert_eq!(b_layers.next(), None);

	Ok(Phase1Output {
		eval_point,
		b_leaves_claims: claims,
	})
}

// PHASE TWO: frobenius

// PHASE THREE: painful sumcheck

fn prove_phase_3<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	// v sumcheck stuff
	twisted_eval_points: Vec<Vec<F>>,
	twisted_claims: Vec<F>,
	v_buffer: FieldBuffer<P>,
	b_exponents: &[u64],
	// c sumcheck stuff
	c_layer: (FieldBuffer<P>, FieldBuffer<P>),
	c_eval_point: Vec<F>,
	c_claim: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase3Output<F>, Error> {
	let n_vars = v_buffer.log_len();

	// make v_prover
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

	if b_exponents.len() != 1 << n_vars {
		return Err(Error::LengthMismatch(b_exponents.len(), 1 << n_vars));
	}

	let mut v_prover = VProver::new(v_buffer, b_exponents, twisted_eval_points, twisted_claims);

	if v_prover.n_vars() != n_vars {
		return Err(Error::LengthMismatch(v_prover.n_vars(), n_vars));
	}

	// make c_prover

	if c_layer.0.log_len() != n_vars {
		return Err(Error::BufferEvalPointMismatch(c_layer.0.log_len(), n_vars));
	}
	if c_layer.1.log_len() != n_vars {
		return Err(Error::BufferEvalPointMismatch(c_layer.1.log_len(), n_vars));
	}

	if c_eval_point.len() != n_vars {
		return Err(Error::LengthMismatch(c_eval_point.len(), n_vars));
	}

	let c_layer = vec![c_layer];
	let evals = vec![c_claim];
	let mut c_prover = BivariateMlecheckProver::new(c_layer, &c_eval_point, &evals)
		.expect("checked input metrics");

	if c_prover.n_vars() != n_vars {
		return Err(Error::LengthMismatch(c_prover.n_vars(), n_vars));
	}

	// batch sumcheck

	let batch_coeff: F = transcript.sample();

	let mut challenges = vec![];

	for _ in 0..n_vars {
		let v_round_coeffs_vec: Vec<RoundCoeffs<F>> =
			v_prover.execute().map_err(Error::from_sumcheck_execute)?;
		let c_round_coeffs_vec: Vec<RoundCoeffs<F>> =
			c_prover.execute().map_err(Error::from_sumcheck_execute)?;

		if v_round_coeffs_vec.len() != 64 {
			return Err(Error::LengthMismatch(v_round_coeffs_vec.len(), 64));
		}
		if c_round_coeffs_vec.len() != 1 {
			return Err(Error::LengthMismatch(c_round_coeffs_vec.len(), 1));
		}

		let mut round_coeffs_vec = v_round_coeffs_vec;
		round_coeffs_vec.extend(c_round_coeffs_vec);

		let round_coeffs: RoundCoeffs<F> = round_coeffs_vec
			.iter()
			.rev()
			.fold(RoundCoeffs::default(), |acc, round_coeffs| acc * batch_coeff + round_coeffs);

		let round_proof = round_coeffs.truncate();
		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		let challenge = transcript.sample();
		challenges.push(challenge);

		v_prover
			.fold(challenge)
			.map_err(Error::from_sumcheck_fold)?;
		c_prover
			.fold(challenge)
			.map_err(Error::from_sumcheck_fold)?;
	}

	challenges.reverse();

	let v_prover_claims = v_prover.finish().map_err(Error::from_sumcheck_finish)?;
	if v_prover_claims.len() != 64 + 1 {
		return Err(Error::LengthMismatch(v_prover_claims.len(), 64 + 1));
	}
	let b_exponent_claims = v_prover_claims[..64].to_vec();
	let v_claim = v_prover_claims[64];

	let mut c_prover_claims = c_prover.finish().unwrap();
	if c_prover_claims.len() != 2 {
		return Err(Error::LengthMismatch(c_prover_claims.len(), 2));
	}
	let last_c_lo_claim = c_prover_claims.pop().expect("contains 2 buffers");
	let last_c_hi_claim = c_prover_claims.pop().expect("contains 1 buffer");

	transcript.message().write_scalar_slice(&v_prover_claims);
	transcript.message().write_scalar_slice(&c_prover_claims);

	Ok(Phase3Output {
		eval_point: challenges,
		b_exponent_claims,
		v_claim,
		c_claims: (last_c_lo_claim, last_c_hi_claim),
	})
}

// PHASE 4: most of a_layers and c_layers

fn prove_phase_4<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	eval_point: Vec<F>,
	// a stuff
	a_layers: &mut Layers<P>,
	a_last_layer_claim: F,
	// c stuff
	c_layers: &mut Layers<P>,
	c_lo_last_layer_claim: F,
	c_hi_last_layer_claim: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase4Output<F>, Error> {
	let mut eval_point = eval_point.to_vec();
	let mut claims = vec![
		a_last_layer_claim,
		c_lo_last_layer_claim,
		c_hi_last_layer_claim,
	];

	for depth in (1..6).rev() {
		let a_layer_buffer_count = 1 << (6 - depth);
		let c_layer_buffer_count = 2 * a_layer_buffer_count;

		let claims_count = (a_layer_buffer_count + c_layer_buffer_count) / 2;
		if claims.len() != claims_count {
			return Err(Error::LengthMismatch(claims.len(), claims_count));
		}

		let a_layer = a_layers.next().expect("taking layer layer_num > 0");
		if a_layer.len() != a_layer_buffer_count {
			return Err(Error::LayerClaimsMismatch(a_layer.len(), a_layer_buffer_count));
		}

		let c_layer = c_layers.next().expect("taking layer layer_num > 0");
		if c_layer.len() != c_layer_buffer_count {
			return Err(Error::LayerClaimsMismatch(c_layer.len(), c_layer_buffer_count));
		}

		let mut layer = Vec::with_capacity(a_layer.len() + c_layer.len());
		layer.extend(a_layer);
		layer.extend(c_layer);

		let HandleLayerOutput {
			eval_point: new_eval_point,
			claims: new_claims,
		} = prove_layer(layer, eval_point, claims, transcript)?;

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

fn prove_phase_5<'a, F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	// a and c stuff
	a_c_eval_point: Vec<F>,
	a_c_evals: Vec<F>,
	mut a_layers: Layers<P>,
	mut c_layers: Layers<P>,
	// b stuff
	b_exponents: &[u64],
	b_eval_point: Vec<F>,
	b_exponent_evals: Vec<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase5Output<F>, Error> {
	let n_vars = a_c_eval_point.len();

	// make layer_prover

	let a_layer = a_layers.next().expect("taking layer 0");
	if a_layer.len() != 64 {
		return Err(Error::LayerClaimsMismatch(a_layer.len(), 64));
	}
	debug_assert_eq!(a_layers.next(), None);

	let c_layer = c_layers.next().expect("taking layer 0");
	if c_layer.len() != 128 {
		return Err(Error::LayerClaimsMismatch(c_layer.len(), 128));
	}
	debug_assert_eq!(c_layers.next(), None);

	let mut layer = Vec::with_capacity(a_layer.len() + c_layer.len());
	layer.extend(a_layer);
	layer.extend(c_layer);

	debug_assert_eq!(layer.len(), 64 + 128);
	if a_c_evals.len() != 32 + 64 {
		return Err(Error::LayerClaimsMismatch(a_c_evals.len(), 32 + 64));
	}

	let mut a_c_prover =
		BivariateMlecheckProver::new(make_pairs(layer), &a_c_eval_point, &a_c_evals)
			.expect("checked input metrics");

	// make rerand_prover

	if b_exponents.len() != 1 << b_eval_point.len() {
		return Err(Error::LengthMismatch(b_exponents.len(), 1 << b_eval_point.len()));
	}
	if b_exponent_evals.len() != 64 {
		return Err(Error::LengthMismatch(b_exponent_evals.len(), 64));
	}

	if b_eval_point.len() != n_vars {
		return Err(Error::LengthMismatch(b_eval_point.len(), n_vars));
	}

	fn make_multilinear<P: PackedField>(i: usize, exp: &[u64]) -> FieldBuffer<P> {
		let packed_elements = exp
			.iter()
			.map(|exp| {
				if exp & (1 << i) == 0 {
					P::Scalar::zero()
				} else {
					P::Scalar::one()
				}
			})
			.collect_vec();

		FieldBuffer::from_values(&packed_elements).expect("input length is power of 2")
	}
	let multilinears = (0..64)
		.map(|i| make_multilinear::<P>(i, &b_exponents))
		.collect_vec();

	let mut b_prover =
		RerandMlecheckProver::<P>::new(multilinears, &b_eval_point, &b_exponent_evals)
			.expect("checked input metrics");

	// batch sumcheck

	let batch_coeff: F = transcript.sample();

	let mut challenges = vec![];

	for _ in 0..n_vars {
		let a_c_round_coeffs_vec = a_c_prover.execute().map_err(Error::from_sumcheck_execute)?;
		if a_c_round_coeffs_vec.len() != 32 + 64 {
			return Err(Error::LengthMismatch(a_c_round_coeffs_vec.len(), 32 + 64));
		}

		let b_round_coeffs_vec = b_prover.execute().map_err(Error::from_sumcheck_execute)?;
		if b_round_coeffs_vec.len() != 64 {
			return Err(Error::LengthMismatch(b_round_coeffs_vec.len(), 64));
		}

		let mut round_coeffs_vec: Vec<RoundCoeffs<F>> = a_c_round_coeffs_vec;
		round_coeffs_vec.extend(b_round_coeffs_vec);

		let round_coeffs = round_coeffs_vec
			.iter()
			.rev()
			.fold(RoundCoeffs::default(), |acc, round_coeffs| acc * batch_coeff + round_coeffs);

		let round_proof = round_coeffs.truncate();
		transcript
			.message()
			.write_scalar_slice(round_proof.coeffs());

		let challenge = transcript.sample();
		challenges.push(challenge);

		a_c_prover
			.fold(challenge)
			.map_err(Error::from_sumcheck_fold)?;
		b_prover
			.fold(challenge)
			.map_err(Error::from_sumcheck_fold)?;
	}

	let scaled_a_c_exponent_claims = a_c_prover.finish().map_err(Error::from_sumcheck_finish)?;
	let b_exponent_claims = b_prover.finish().map_err(Error::from_sumcheck_finish)?;

	if scaled_a_c_exponent_claims.len() != 64 + 128 {
		return Err(Error::LengthMismatch(scaled_a_c_exponent_claims.len(), 64 + 128));
	}
	if b_exponent_claims.len() != 64 {
		return Err(Error::LengthMismatch(b_exponent_claims.len(), 64));
	}

	transcript
		.message()
		.write_scalar_slice(&scaled_a_c_exponent_claims);
	transcript.message().write_scalar_slice(&b_exponent_claims);

	Ok(Phase5Output {
		eval_point: a_c_eval_point,
		scaled_a_c_exponent_claims,
		b_exponent_claims,
	})
}

// PROVE

#[derive(Debug)]
pub struct ProveOutput<P: PackedField> {
	pub eval_point: Vec<P::Scalar>,
	pub a_exponent_claims: Vec<P::Scalar>,
	pub b_exponent_claims: Vec<P::Scalar>,
	pub c_lo_exponent_claims: Vec<P::Scalar>,
	pub c_hi_exponent_claims: Vec<P::Scalar>,
}

pub fn prove<'a, F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	n_vars: usize,
	b_exponents: &'a [u64],
	mut a_layers: Layers<P>,
	mut b_layers: Layers<P>,
	mut c_layers: Layers<P>,
	generator: P::Scalar,
	transcript: &mut ProverTranscript<C>,
) -> Result<(), Error> {
	// -> Result<ProveOutput<P>, Error> {
	let initial_eval_point = transcript.sample_vec(n_vars);

	let mut last_b_layer = b_layers.next().expect("taking layer 6");
	if last_b_layer.len() != 1 {
		return Err(Error::LengthMismatch(last_b_layer.len(), 1));
	}
	let last_b_buffer = last_b_layer.pop().expect("contains exactly one buffer");

	let mut last_c_layer = c_layers.next().expect("taking layer 7");
	if last_c_layer.len() != 1 {
		return Err(Error::LengthMismatch(last_c_layer.len(), 1));
	}
	let last_c_buffer = last_c_layer.pop().expect("contains exactly one buffer");

	let (initial_b_eval, initial_c_eval) =
		compute_initial_evals(&initial_eval_point, last_b_buffer, last_c_buffer)?;

	transcript.message().write_scalar(initial_b_eval);
	transcript.message().write_scalar(initial_c_eval);

	// phase 1
	let Phase1Output {
		eval_point: phase_1_eval_point,
		b_leaves_claims: b_tree_leaves_evals,
	} = prove_phase_1(b_layers, initial_eval_point.clone(), initial_b_eval, transcript)?;

	debug_assert_eq!(phase_1_eval_point.len(), n_vars);
	debug_assert_eq!(b_tree_leaves_evals.len(), 64);

	// phase 2
	let Phase2Output {
		twisted_eval_points,
		twisted_claims: twisted_evals,
	} = frobenius::<P::Scalar, P>(phase_1_eval_point, b_tree_leaves_evals);
	debug_assert_eq!(twisted_eval_points.len(), 64);
	debug_assert_eq!(twisted_evals.len(), 64);

	// phase 3
	let mut last_a_layer = a_layers.next().expect("taking layer 6");
	if last_a_layer.len() != 1 {
		return Err(Error::LengthMismatch(last_a_layer.len(), 1));
	}
	let last_a_buffer = last_a_layer.pop().expect("contains exactly one buffer");

	let mut last_c_layer = c_layers.next().expect("taking layer 6");
	if last_c_layer.len() != 2 {
		return Err(Error::LengthMismatch(last_c_layer.len(), 2));
	}
	let last_c_lo_buffer = last_c_layer.pop().expect("contains 2 buffers");
	let last_c_hi_buffer = last_c_layer.pop().expect("contains 1 buffer");

	let Phase3Output {
		eval_point: phase_3_eval_point,
		b_exponent_claims,
		v_claim,
		c_claims,
	} = prove_phase_3(
		twisted_eval_points,
		twisted_evals,
		last_a_buffer,
		b_exponents,
		(last_c_lo_buffer, last_c_hi_buffer),
		initial_eval_point,
		initial_c_eval,
		transcript,
	)?;

	// phase 4
	let Phase4Output {
		eval_point: phase_4_eval_point,
		a_32_c_64_claims,
	} = prove_phase_4(
		phase_3_eval_point.clone(),
		// a stuff
		&mut a_layers,
		v_claim,
		// c stuff
		&mut c_layers,
		c_claims.0,
		c_claims.1,
		transcript,
	)?;

	// phase 5
	let Phase5Output {
		eval_point: phase_5_eval_point,
		scaled_a_c_exponent_claims,
		b_exponent_claims,
	} = prove_phase_5(
		phase_4_eval_point,
		a_32_c_64_claims,
		a_layers,
		c_layers,
		b_exponents,
		phase_3_eval_point,
		b_exponent_claims,
		transcript,
	)?;

	let (a_exponent_claims, c_lo_exponent_claims, c_hi_exponent_claims) =
		normalize_a_c_exponent_evals::<P>(scaled_a_c_exponent_claims, generator);

	// Ok(ProveOutput {
	// 	eval_point: phase_5_eval_point,
	// 	a_exponent_claims,
	// 	b_exponent_claims,
	// 	c_lo_exponent_claims,
	// 	c_hi_exponent_claims,
	// })
	Ok(())
}
