use binius_field::{Field, PackedField};
use binius_math::field_buffer::FieldBuffer;
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use itertools::{Itertools, izip};

use super::*;
use crate::provers::{BivariateProductProver, RerandomizationProver, SumcheckProver, VProver};

fn pair_field_buffers<P: PackedField>(
	layer: Vec<FieldBuffer<P>>,
) -> Vec<(FieldBuffer<P>, FieldBuffer<P>)> {
	layer.into_iter().tuples().collect()
}

/// evaluates the last b and c layers at the given eval point.
fn compute_initial_evals<P: PackedField>(
	eval_point: &[P::Scalar],
	last_b_layer: FieldBuffer<P>,
	last_c_layer: FieldBuffer<P>,
) -> (P::Scalar, P::Scalar) {
	assert_eq!(eval_point.len(), last_b_layer.log_len());
	assert_eq!(eval_point.len(), last_c_layer.log_len());
	todo!()
}

struct ProveLayerOutput<P: PackedField> {
	challenges: Vec<P::Scalar>,
	evals: Vec<P::Scalar>,
}

fn prove_layer<'a, P: PackedField, C: Challenger>(
	layer: Vec<FieldBuffer<P>>,
	eval_point: Vec<P::Scalar>,
	evals: Vec<P::Scalar>,
	transcript: &mut ProverTranscript<C>,
) -> ProveLayerOutput<P> {
	assert_eq!(layer.len(), 2 * evals.len());

	layer
		.iter()
		.for_each(|buf| assert_eq!(buf.log_len(), eval_point.len()));

	let mut prover =
		BivariateProductProver::<P>::new(pair_field_buffers(layer), &eval_point, &evals);

	let batch_coef = transcript.sample();
	let mut challenges = vec![];

	for _ in 0..eval_point.len() {
		let round_coefs = prover.execute(batch_coef).unwrap();

		transcript
			.message()
			.write_scalar_slice(round_coefs.0.as_ref());

		let challenge = transcript.sample();
		challenges.push(challenge);

		prover.fold(challenge).unwrap();
	}

	let new_evals = Box::new(prover).finish().unwrap();
	assert_eq!(new_evals.len(), 2 * evals.len());

	ProveLayerOutput {
		challenges,
		evals: new_evals,
	}
}

// PHASE ONE: b_tree

struct Phase1Output<P: PackedField> {
	eval_point: Vec<P::Scalar>,
	b_tree_leaves_evals: Vec<P::Scalar>,
}

fn prove_phase_1<P: PackedField, C: Challenger>(
	mut b_tree: Layers<P>,
	initial_eval_point: Vec<P::Scalar>,
	initial_eval: P::Scalar,
	transcript: &mut ProverTranscript<C>,
) -> Phase1Output<P> {
	let mut eval_point = initial_eval_point;
	let mut evals = vec![initial_eval];

	for layer_num in (0..6).rev() {
		assert_eq!(evals.len(), 1 << (5 - layer_num));

		let layer = b_tree.next().expect("taking layer layer_num >= 0");
		assert_eq!(layer.len(), 2 * evals.len());

		let ProveLayerOutput {
			challenges: new_eval_point,
			evals: new_evals,
		} = prove_layer(layer, eval_point, evals, transcript);

		eval_point = new_eval_point;
		evals = new_evals;
	}

	assert_eq!(b_tree.next(), None);

	Phase1Output {
		eval_point,
		b_tree_leaves_evals: evals,
	}
}

// PHASE TWO: frobenius

struct Phase2Output<P: PackedField> {
	twisted_eval_points: Vec<Vec<P::Scalar>>,
	twisted_evals: Vec<P::Scalar>,
}

/// for i in 0..64, compute phi^i(eval_point) and phi^i(evals[i])
fn frobenius<P: PackedField>(eval_point: Vec<P::Scalar>, evals: Vec<P::Scalar>) -> Phase2Output<P> {
	let mut twisted_eval_points = vec![];
	let mut twisted_evals = vec![];

	todo!();

	Phase2Output {
		twisted_eval_points,
		twisted_evals,
	}
}

// PHASE THREE: painful sumcheck

struct Phase3Output<P: PackedField> {
	eval_point: Vec<P::Scalar>,
	b_exponent_evals: Vec<P::Scalar>,
	v_eval: P::Scalar,
	c_evals: (P::Scalar, P::Scalar),
}

fn prove_phase_3<P: PackedField, C: Challenger>(
	n_vars: usize,
	// v sumcheck stuff
	twisted_eval_points: Vec<Vec<P::Scalar>>,
	twisted_evals: Vec<P::Scalar>,
	v_buffer: FieldBuffer<P>,
	b_exponents: &[u64],
	// c sumcheck stuff
	c_layer: (FieldBuffer<P>, FieldBuffer<P>),
	c_eval_point: Vec<P::Scalar>,
	c_eval: P::Scalar,
	transcript: &mut ProverTranscript<C>,
) -> Phase3Output<P> {
	let mut v_prover = VProver::new(v_buffer, b_exponents, twisted_eval_points, twisted_evals);

	let layer = vec![c_layer];
	let evals = vec![c_eval];
	let mut c_prover = BivariateProductProver::new(layer, &c_eval_point, &evals);

	assert_eq!(v_prover.n_vars(), n_vars);
	assert_eq!(c_prover.n_vars(), n_vars);

	let v_batch_coef = transcript.sample();
	let c_batch_coef = transcript.sample();

	let mut challenges = vec![];

	for _ in 0..n_vars {
		let v_round_coefs = v_prover.execute(v_batch_coef).unwrap();
		let c_round_coefs = c_prover.execute(c_batch_coef).unwrap();

		let round_coefs = v_round_coefs * v_batch_coef + &(c_round_coefs * c_batch_coef);

		transcript
			.message()
			.write_scalar_slice(round_coefs.0.as_ref());

		let challenge = transcript.sample();
		challenges.push(challenge);

		v_prover.fold(challenge).unwrap();
		c_prover.fold(challenge).unwrap();
	}

	let v_evals = Box::new(v_prover).finish().unwrap();
	assert_eq!(v_evals.len(), 64 + 1);

	let mut c_evals = Box::new(c_prover).finish().unwrap();
	assert_eq!(c_evals.len(), 2);
	let last_c_lo_eval = c_evals.pop().expect("contains 2 buffers");
	let last_c_hi_eval = c_evals.pop().expect("contains 1 buffer");

	let b_exponent_evals = v_evals[..64].to_vec();
	let v_eval = v_evals[64];

	Phase3Output {
		eval_point: challenges,
		b_exponent_evals,
		v_eval,
		c_evals: (last_c_lo_eval, last_c_hi_eval),
	}
}

// PHASE 4: most of a_tree and c_tree

struct Phase4Output<P: PackedField> {
	eval_point: Vec<P::Scalar>,
	a_32_c_64_evals: Vec<P::Scalar>,
}

fn prove_phase_4<P: PackedField, C: Challenger>(
	eval_point: &[P::Scalar],
	// a stuff
	a_layers: &mut Layers<P>,
	a_last_layer_eval: P::Scalar,
	// c stuff
	c_layers: &mut Layers<P>,
	c_lo_last_layer_eval: P::Scalar,
	c_hi_last_layer_eval: P::Scalar,
	transcript: &mut ProverTranscript<C>,
) -> Phase4Output<P> {
	let mut eval_point = eval_point.to_vec();
	let mut evals = vec![
		a_last_layer_eval,
		c_lo_last_layer_eval,
		c_hi_last_layer_eval,
	];

	for layer_num in (1..6).rev() {
		let k = 6 - layer_num;
		assert_eq!(evals.len(), 3 * (1 << k) / 2);

		let a_layer = a_layers.next().expect("taking layer layer_num > 0");
		assert_eq!(a_layer.len(), 1 << k);

		let c_layer = c_layers.next().expect("taking layer layer_num > 0");
		assert_eq!(c_layer.len(), 2 * (1 << k));

		let mut layer = Vec::with_capacity(a_layer.len() + c_layer.len());
		layer.extend(a_layer);
		layer.extend(c_layer);

		assert_eq!(layer.len(), evals.len());

		let ProveLayerOutput {
			challenges: new_eval_point,
			evals: new_evals,
		} = prove_layer(layer, eval_point, evals, transcript);

		eval_point = new_eval_point;
		evals = new_evals;
	}

	assert_eq!(evals.len(), 32 + 2 * 32);

	Phase4Output {
		eval_point,
		a_32_c_64_evals: evals,
	}
}

// PHASE 5: final layer

struct Phase5Output<P: PackedField> {
	eval_point: Vec<P::Scalar>,
	scaled_a_c_exponent_evals: Vec<P::Scalar>,
	b_exponent_evals: Vec<P::Scalar>,
}

fn prove_phase_5<'a, P: PackedField, C: Challenger>(
	// a and c stuff
	eval_point: Vec<P::Scalar>,
	evals: Vec<P::Scalar>,
	mut a_layers: Layers<P>,
	mut c_layers: Layers<P>,
	// b stuff
	b_exponents: &[u64],
	b_eval_point: Vec<P::Scalar>,
	b_exponent_evals: Vec<P::Scalar>,
	transcript: &mut ProverTranscript<C>,
) -> Phase5Output<P> {
	let a_layer = a_layers.next().expect("taking layer 0");
	assert_eq!(a_layer.len(), 64);
	assert_eq!(a_layers.next(), None);

	let c_layer = c_layers.next().expect("taking layer 0");
	assert_eq!(c_layer.len(), 128);
	assert_eq!(c_layers.next(), None);

	let mut layer = Vec::with_capacity(a_layer.len() + c_layer.len());
	layer.extend(a_layer);
	layer.extend(c_layer);

	assert_eq!(layer.len(), 192);
	assert_eq!(evals.len(), 32 + 64);

	let mut layer_prover =
		BivariateProductProver::new(pair_field_buffers(layer), &eval_point, &evals);

	let mut rerand_prover =
		RerandomizationProver::<P>::new(b_exponents, b_eval_point, b_exponent_evals);

	let layer_batch_coef = transcript.sample();
	let rerand_batch_coef = transcript.sample();

	let mut challenges = vec![];

	for _ in 0..eval_point.len() {
		let layer_round_coefs = layer_prover.execute(layer_batch_coef).unwrap();
		let rerand_round_coefs = rerand_prover.execute(rerand_batch_coef).unwrap();

		let round_coefs =
			layer_round_coefs * layer_batch_coef + &(rerand_round_coefs * rerand_batch_coef);

		transcript
			.message()
			.write_scalar_slice(round_coefs.0.as_ref());

		let challenge = transcript.sample();
		challenges.push(challenge);

		layer_prover.fold(challenge).unwrap();
		rerand_prover.fold(challenge).unwrap();
	}

	let scaled_a_c_exponent_evals = Box::new(layer_prover).finish().unwrap();
	let b_exponent_evals = Box::new(rerand_prover).finish().unwrap();
	assert_eq!(scaled_a_c_exponent_evals.len(), 192);
	assert_eq!(b_exponent_evals.len(), 64);

	Phase5Output {
		eval_point,
		scaled_a_c_exponent_evals,
		b_exponent_evals,
	}
}

fn normalize_a_c_exponent_evals<P: PackedField>(
	evals: Vec<P::Scalar>,
	generator: P::Scalar,
) -> (Vec<P::Scalar>, Vec<P::Scalar>, Vec<P::Scalar>) {
	assert_eq!(evals.len(), 64 + 2 * 64);
	// for i in 0..64: evals[i] = (1-EvalMLE_i)*1 + EvalMLE_i*g^{2^i} = EvalMLE_i*(g^{2^i}-1) + 1
	// where EvalMLE_i is the evaluation of the multilinear extension of bit i of the exponents of
	// `a` (the point of evaluation is irrelevant in this function)
	// we can then compute desired evaluation EvalMLE_i as (eval[i] - 1) / (g^{2^i}-1)
	// similarly for `c` for evals[64..192] and i in 0..128

	let mut a_scaled_evals = evals;
	let mut c_scaled_evals = a_scaled_evals.split_off(64);
	let mut c_lo_scaled_evals = c_scaled_evals.split_off(64);
	let mut c_hi_scaled_evals = c_scaled_evals;

	let conjugates: Vec<_> = std::iter::successors(Some(generator), |&prev| Some(prev.square()))
		.take(128)
		.collect();

	izip!(conjugates[..64].iter(), a_scaled_evals.iter_mut(), c_lo_scaled_evals.iter_mut())
		.for_each(|(conjugate, a_eval, c_lo_eval)| {
			*a_eval -= P::Scalar::one();
			*a_eval *= (*conjugate - P::Scalar::one()).invert().expect("non-zero");
			*c_lo_eval -= P::Scalar::one();
			*c_lo_eval *= (*conjugate - P::Scalar::one()).invert().expect("non-zero");
		});

	izip!(conjugates[64..].iter(), c_hi_scaled_evals.iter_mut()).for_each(
		|(conjugate, c_hi_eval)| {
			*c_hi_eval -= P::Scalar::one();
			*c_hi_eval *= (*conjugate - P::Scalar::one()).invert().expect("non-zero");
		},
	);

	(a_scaled_evals, c_lo_scaled_evals, c_hi_scaled_evals)
}

// PROVE

struct ProveOutput<P: PackedField> {
	eval_point: Vec<P::Scalar>,
	a_exponent_evals: Vec<P::Scalar>,
	b_exponent_evals: Vec<P::Scalar>,
	c_lo_exponent_evals: Vec<P::Scalar>,
	c_hi_exponent_evals: Vec<P::Scalar>,
}

fn prove_backwards<'a, P: PackedField, C: Challenger>(
	n_vars: usize,
	b_exponents: &'a [u64],
	mut a_layers: Layers<P>,
	mut b_layers: Layers<P>,
	mut c_layers: Layers<P>,
	generator: P::Scalar,
	transcript: &mut ProverTranscript<C>,
) -> ProveOutput<P> {
	let initial_eval_point = transcript.sample_vec(n_vars);

	let mut last_b_layer = b_layers.next().expect("taking layer 6");
	let last_b_buffer = last_b_layer.pop().expect("contains exactly one buffer");

	let mut last_c_layer = c_layers.next().expect("taking layer 7");
	let last_c_buffer = last_c_layer.pop().expect("contains exactly one buffer");

	let (initial_b_eval, initial_c_eval) =
		compute_initial_evals(&initial_eval_point, last_b_buffer, last_c_buffer);

	// phase 1
	let Phase1Output {
		eval_point: phase_1_eval_point,
		b_tree_leaves_evals,
	} = prove_phase_1(b_layers, initial_eval_point.clone(), initial_b_eval, transcript);

	assert_eq!(phase_1_eval_point.len(), n_vars);
	assert_eq!(b_tree_leaves_evals.len(), 64);

	// phase 2
	let Phase2Output {
		twisted_eval_points,
		twisted_evals,
	} = frobenius::<P>(phase_1_eval_point, b_tree_leaves_evals);
	assert_eq!(twisted_eval_points.len(), 64);
	assert_eq!(twisted_evals.len(), 64);

	// phase 3
	let mut last_a_layer = a_layers.next().expect("taking layer 6");
	let last_a_buffer = last_a_layer.pop().expect("contains exactly one buffer");

	let mut last_c_layer = c_layers.next().expect("taking layer 6");
	assert_eq!(last_c_layer.len(), 2);
	let last_c_lo_buffer = last_c_layer.pop().expect("contains 2 buffers");
	let last_c_hi_buffer = last_c_layer.pop().expect("contains 1 buffer");

	let Phase3Output {
		eval_point: phase_3_eval_point,
		b_exponent_evals,
		v_eval: a_last_layer_eval,
		c_evals,
	} = prove_phase_3(
		n_vars,
		twisted_eval_points,
		twisted_evals,
		last_a_buffer,
		b_exponents,
		(last_c_lo_buffer, last_c_hi_buffer),
		initial_eval_point,
		initial_c_eval,
		transcript,
	);

	// phase 4
	let Phase4Output {
		eval_point: phase_4_eval_point,
		a_32_c_64_evals,
	} = prove_phase_4(
		&phase_3_eval_point,
		// a stuff
		&mut a_layers,
		a_last_layer_eval,
		// c stuff
		&mut c_layers,
		c_evals.0,
		c_evals.1,
		transcript,
	);

	// phase 5
	let Phase5Output {
		eval_point: phase_5_eval_point,
		scaled_a_c_exponent_evals,
		b_exponent_evals,
	} = prove_phase_5(
		phase_4_eval_point,
		a_32_c_64_evals,
		a_layers,
		c_layers,
		b_exponents,
		phase_3_eval_point,
		b_exponent_evals,
		transcript,
	);

	let (a_exponent_evals, c_lo_exponent_evals, c_hi_exponent_evals) =
		normalize_a_c_exponent_evals::<P>(scaled_a_c_exponent_evals, generator);

	ProveOutput {
		eval_point: phase_5_eval_point,
		a_exponent_evals,
		b_exponent_evals,
		c_lo_exponent_evals,
		c_hi_exponent_evals,
	}
}
