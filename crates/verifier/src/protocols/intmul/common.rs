use binius_field::{Field, PackedField};
use itertools::izip;

pub struct Phase1Output<F> {
	pub eval_point: Vec<F>,
	pub b_leaves_claims: Vec<F>,
}

pub struct Phase2Output<F> {
	pub twisted_eval_points: Vec<Vec<F>>,
	pub twisted_claims: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct Phase3Output<F> {
	pub eval_point: Vec<F>,
	pub b_exponent_claims: Vec<F>,
	pub v_claim: F,
	pub c_lo_last_layer_claim: F,
	pub c_hi_last_layer_claim: F,
}

pub fn make_phase_3_output<F>(
	eval_point: Vec<F>,
	mut v_prover_claims: Vec<F>,
	mut c_prover_claims: Vec<F>,
) -> Phase3Output<F> {
	assert_eq!(v_prover_claims.len(), 64 + 1);
	let v_claim = v_prover_claims.pop().expect("contains 65 buffers");
	let b_exponent_claims: Vec<F> = v_prover_claims;
	assert_eq!(b_exponent_claims.len(), 64);

	assert_eq!(c_prover_claims.len(), 2);
	let c_hi_last_layer_claim = c_prover_claims.pop().expect("contains 2 buffers");
	let c_lo_last_layer_claim = c_prover_claims.pop().expect("contains 1 buffer");

	Phase3Output {
		eval_point,
		b_exponent_claims,
		v_claim,
		c_lo_last_layer_claim,
		c_hi_last_layer_claim,
	}
}

pub struct Phase4Output<F> {
	pub eval_point: Vec<F>,
	pub a_32_c_64_claims: Vec<F>,
}

pub struct Phase5Output<F> {
	pub eval_point: Vec<F>,
	pub scaled_a_c_exponent_claims: Vec<F>,
	pub b_exponent_claims: Vec<F>,
}

/// for i in 0..64, compute phi^i(eval_point) and phi^i(evals[i])
///
/// remember how this actually works.
/// we need to raise to the 128-i.
pub fn frobenius<F: Field, P: PackedField<Scalar = F>>(
	eval_point: Vec<F>,
	evals: Vec<F>,
) -> Phase2Output<F> {
	let twisted_eval_points = (0..64)
		.map(|i| {
			eval_point
				.iter()
				.map(|&var| (0..(128 - i)).fold(var, |acc, _| acc.square()))
				.collect::<Vec<_>>()
		})
		.collect::<Vec<_>>();

	let twisted_claims = evals
		.into_iter()
		.enumerate()
		.map(|(i, eval)| (0..(128 - i)).fold(eval, |acc, _| acc.square()))
		.collect::<Vec<_>>();

	Phase2Output {
		twisted_eval_points,
		twisted_claims,
	}
}

pub fn normalize_a_c_exponent_evals<P: PackedField>(
	evals: Vec<P::Scalar>,
	generator: P::Scalar,
) -> (Vec<P::Scalar>, Vec<P::Scalar>, Vec<P::Scalar>) {
	debug_assert_eq!(evals.len(), 64 + 2 * 64);
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
