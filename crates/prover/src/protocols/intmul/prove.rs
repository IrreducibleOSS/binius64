use binius_field::{Field, PackedField};
use binius_math::{field_buffer::FieldBuffer, multilinear::eq::eq_ind_partial_eval};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_verifier::protocols::{
	intmul::common::{
		Phase1Output, Phase2Output, Phase3Output, Phase4Output, Phase5Output, frobenius,
		make_phase_3_output, normalize_a_c_exponent_evals,
	},
	sumcheck::common::BatchSumcheckOutput,
};
use either::Either;
use itertools::{Itertools, izip};

use super::{
	error::Error,
	execute::LayersIterator,
	provers::{Claim, VProver},
};
use crate::protocols::sumcheck::{
	batch::batch_prove, bivariate_mle::BivariateMlecheckProver, rerand_mle::RerandMlecheckProver,
};

fn make_pairs<T>(layer: Vec<T>) -> Vec<(T, T)> {
	layer.into_iter().tuples().collect()
}

pub fn compute_eval<F: Field, P: PackedField<Scalar = F>>(
	eval_point: &[F],
	buffer: FieldBuffer<P>,
) -> F {
	let eq_expansion = eq_ind_partial_eval::<P>(eval_point);
	let packed_eval: P = izip!(eq_expansion.as_ref(), buffer.as_ref())
		.fold(P::default(), |acc, (&eq, &buf)| acc + eq * buf);
	packed_eval.iter().sum()
}

pub fn compute_initial_evals<F: Field, P: PackedField<Scalar = F>>(
	eval_point: &[F],
	last_b_buffer: FieldBuffer<P>,
	last_c_buffer: FieldBuffer<P>,
) -> Result<(F, F), Error> {
	assert_eq!(eval_point.len(), last_b_buffer.log_len());
	assert_eq!(eval_point.len(), last_c_buffer.log_len());

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

// PHASE ONE: b_layers

fn prove_phase_1<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	b_layers: LayersIterator<P>,
	initial_eval_point: Vec<F>,
	initial_claim: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase1Output<F>, Error> {
	let mut eval_point = initial_eval_point;
	let mut claims = vec![initial_claim];

	for (depth, layer) in izip!((0..6).rev(), b_layers) {
		let layer_buffer_count = 1 << (6 - depth);
		assert_eq!(claims.len(), layer_buffer_count / 2);
		assert_eq!(layer.len(), layer_buffer_count);

		let prover = BivariateMlecheckProver::new(make_pairs(layer), &eval_point, &claims)
			.map_err(Error::from_sumcheck_new)?;

		let BatchSumcheckOutput {
			challenges,
			mut multilinear_evals,
		} = batch_prove(vec![prover], transcript).map_err(Error::from_sumcheck_batch)?;

		eval_point = challenges;
		claims = multilinear_evals.pop().expect("there is one prover");
	}

	debug_assert_eq!(claims.len(), 64);

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
	last_c_lo_buffer: FieldBuffer<P>,
	last_c_hi_buffer: FieldBuffer<P>,
	c_eval_point: Vec<F>,
	c_claim: F,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase3Output<F>, Error> {
	let n_vars = v_buffer.log_len();

	// make v_prover
	assert_eq!(twisted_eval_points.len(), 64);
	assert_eq!(twisted_claims.len(), 64);
	for twisted_eval_point in &twisted_eval_points {
		assert_eq!(twisted_eval_point.len(), n_vars);
	}

	assert_eq!(b_exponents.len(), 1 << n_vars);

	let claims = twisted_eval_points
		.into_iter()
		.zip(twisted_claims)
		.map(|(eval_point, claim)| Claim { eval_point, claim })
		.collect_vec();
	let v_prover = VProver::new(v_buffer.clone(), claims, b_exponents, 0);

	// make c_prover

	assert_eq!(last_c_lo_buffer.log_len(), n_vars);
	assert_eq!(last_c_hi_buffer.log_len(), n_vars);
	assert_eq!(c_eval_point.len(), n_vars);

	let c_layer = vec![(last_c_lo_buffer, last_c_hi_buffer)];
	let evals = vec![c_claim];
	let c_prover = BivariateMlecheckProver::new(c_layer, &c_eval_point, &evals)
		.map_err(Error::from_sumcheck_new)?;

	// batch sumcheck

	let provers = vec![Either::Left(v_prover), Either::Right(c_prover)];
	let BatchSumcheckOutput {
		challenges,
		mut multilinear_evals,
	} = batch_prove(provers, transcript).map_err(Error::from_sumcheck_batch)?;

	assert_eq!(multilinear_evals.len(), 2);
	let c_prover_claims = multilinear_evals.pop().expect("size 2");
	let v_prover_claims = multilinear_evals.pop().expect("size 1");

	Ok(make_phase_3_output(challenges, v_prover_claims, c_prover_claims))
}

// PHASE 4: most of a_layers and c_layers

fn prove_phase_4<F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	eval_point: Vec<F>,
	// a stuff
	a_layers: &mut LayersIterator<P>,
	a_last_layer_claim: F,
	// c stuff
	c_layers: &mut LayersIterator<P>,
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

	for (depth, a_layer, c_layer) in izip!((1..6).rev(), a_layers, c_layers) {
		assert_eq!(a_layer.len(), 1 << (6 - depth));
		assert_eq!(c_layer.len(), 2 * a_layer.len());

		assert_eq!(claims.len(), (a_layer.len() + c_layer.len()) / 2);

		let mut layer = Vec::with_capacity(a_layer.len() + c_layer.len());
		layer.extend(a_layer);
		layer.extend(c_layer);

		let prover = BivariateMlecheckProver::new(make_pairs(layer), &eval_point, &claims)
			.map_err(Error::from_sumcheck_new)?;

		let provers = vec![prover];
		let BatchSumcheckOutput {
			challenges,
			mut multilinear_evals,
		} = batch_prove(provers, transcript).map_err(Error::from_sumcheck_batch)?;

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

fn prove_phase_5<'a, F: Field, P: PackedField<Scalar = F>, C: Challenger>(
	// a and c stuff
	a_c_eval_point: Vec<F>,
	a_c_evals: Vec<F>,
	mut a_layers: LayersIterator<P>,
	mut c_layers: LayersIterator<P>,
	// b stuff
	b_exponents: &[u64],
	b_eval_point: Vec<F>,
	b_exponent_evals: Vec<F>,
	transcript: &mut ProverTranscript<C>,
) -> Result<Phase5Output<F>, Error> {
	let n_vars = a_c_eval_point.len();

	// make a_c_prover

	let a_layer = a_layers.next().expect("taking layer 0");
	assert_eq!(a_layer.len(), 64);
	debug_assert_eq!(a_layers.next(), None);

	let c_layer = c_layers.next().expect("taking layer 0");
	assert_eq!(c_layer.len(), 128);
	debug_assert_eq!(c_layers.next(), None);

	let mut layer = Vec::with_capacity(a_layer.len() + c_layer.len());
	layer.extend(a_layer);
	layer.extend(c_layer);

	debug_assert_eq!(layer.len(), 64 + 128);
	assert_eq!(a_c_evals.len(), 32 + 64);

	let a_c_prover = BivariateMlecheckProver::new(make_pairs(layer), &a_c_eval_point, &a_c_evals)
		.map_err(Error::from_sumcheck_new)?;

	// make b_prover

	assert_eq!(b_exponents.len(), 1 << b_eval_point.len());
	assert_eq!(b_exponent_evals.len(), 64);
	assert_eq!(b_eval_point.len(), n_vars);

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

	let b_prover = RerandMlecheckProver::<P>::new(multilinears, &b_eval_point, &b_exponent_evals)
		.expect("checked input metrics");

	// batch sumcheck

	let BatchSumcheckOutput {
		challenges,
		mut multilinear_evals,
	} = batch_prove(vec![Either::Left(a_c_prover), Either::Right(b_prover)], transcript)
		.map_err(Error::from_sumcheck_batch)?;

	assert_eq!(multilinear_evals.len(), 2);
	let b_exponent_claims = multilinear_evals.pop().expect("size 2");
	let scaled_a_c_exponent_claims = multilinear_evals.pop().expect("size 1");

	assert_eq!(scaled_a_c_exponent_claims.len(), 64 + 128);
	assert_eq!(b_exponent_claims.len(), 64);

	Ok(Phase5Output {
		eval_point: challenges,
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
	mut a_layers: LayersIterator<P>,
	mut b_layers: LayersIterator<P>,
	mut c_layers: LayersIterator<P>,
	generator: P::Scalar,
	transcript: &mut ProverTranscript<C>,
) -> Result<ProveOutput<P>, Error> {
	let initial_eval_point = transcript.sample_vec(n_vars);

	let mut b_last_layer = b_layers.next().expect("taking layer 6");
	assert_eq!(b_last_layer.len(), 1);
	let b_last_buffer = b_last_layer.pop().expect("contains exactly one buffer");

	let mut c_last_layer = c_layers.next().expect("taking layer 7");
	assert_eq!(c_last_layer.len(), 1);
	let c_last_buffer = c_last_layer.pop().expect("contains exactly one buffer");

	let (b_initial_eval, c_initial_eval) =
		compute_initial_evals(&initial_eval_point, b_last_buffer, c_last_buffer)?;

	transcript.message().write_scalar(b_initial_eval);
	transcript.message().write_scalar(c_initial_eval);

	// phase 1
	let Phase1Output {
		eval_point: phase_1_eval_point,
		b_leaves_claims: b_tree_leaves_evals,
	} = prove_phase_1(b_layers, initial_eval_point.clone(), b_initial_eval, transcript)?;

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
	let mut a_last_layer = a_layers.next().expect("taking layer 6");
	assert_eq!(a_last_layer.len(), 1);
	let a_last_buffer = a_last_layer.pop().expect("contains exactly one buffer");

	let mut c_next_layer = c_layers.next().expect("taking layer 6");
	assert_eq!(c_next_layer.len(), 2);
	let c_hi_last_buffer = c_next_layer.pop().expect("contains 2 buffers");
	let c_lo_last_buffer = c_next_layer.pop().expect("contains 1 buffer");

	let Phase3Output {
		eval_point: phase_3_eval_point,
		b_exponent_claims,
		v_claim,
		c_lo_last_layer_claim: c_lo_last_claim,
		c_hi_last_layer_claim: c_hi_last_claim,
	} = prove_phase_3(
		// v sumcheck stuff
		twisted_eval_points,
		twisted_evals,
		a_last_buffer,
		b_exponents,
		// c sumcheck stuff
		c_lo_last_buffer,
		c_hi_last_buffer,
		initial_eval_point,
		c_initial_eval,
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
		c_lo_last_claim,
		c_hi_last_claim,
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

	// let eval_point = vec![];
	// let a_exponent_claims = vec![];
	// let b_exponent_claims = vec![];
	// let c_lo_exponent_claims = vec![];
	// let c_hi_exponent_claims = vec![];
	Ok(ProveOutput {
		eval_point: phase_5_eval_point,
		a_exponent_claims,
		b_exponent_claims,
		c_lo_exponent_claims,
		c_hi_exponent_claims,
	})
	// Ok(())
}
