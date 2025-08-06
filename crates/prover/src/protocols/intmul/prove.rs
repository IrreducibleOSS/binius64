// Copyright 2025 Irreducible Inc.

use std::marker::PhantomData;

use binius_field::{BinaryField, PackedField};
use binius_math::{
	BinarySubspace, field_buffer::FieldBuffer, multilinear::evaluate::evaluate,
	univariate::lagrange_evals,
};
use binius_transcript::{
	ProverTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::bitwise::Bitwise;
use binius_verifier::{
	config::LOG_WORD_SIZE_BITS,
	protocols::intmul::common::{
		IntMulOutput, Phase1Output, Phase2Output, Phase3Output, Phase4Output, Phase5Output,
		frobenius_twist, make_phase_3_output, normalize_a_c_exponent_evals,
	},
};
use either::Either;
use itertools::{Itertools, izip};

use super::{error::Error, witness::Witness};
use crate::protocols::sumcheck::{
	MleToSumCheckDecorator,
	batch::{BatchSumcheckOutput, batch_prove},
	bivariate_product_mle::BivariateProductMlecheckProver,
	bivariate_product_multi_mle::BivariateProductMultiMlecheckProver,
	rerand_mle::RerandMlecheckProver,
	selector_mle::{Claim, SelectorMlecheckProver},
};

/// A helper structure that encapsulates switchover settings and the prover transcript for
/// the integer multiplication protocol.
pub struct IntMulProver<'a, P, B, S, C: Challenger> {
	_p_marker: PhantomData<P>,
	_b_marker: PhantomData<B>,
	_s_marker: PhantomData<S>,

	switchover: usize,
	transcript: &'a mut ProverTranscript<C>,
}

impl<'a, P, B, S, C: Challenger> IntMulProver<'a, P, B, S, C> {
	pub fn new(switchover: usize, transcript: &'a mut ProverTranscript<C>) -> Self {
		Self {
			_p_marker: PhantomData,
			_b_marker: PhantomData,
			_s_marker: PhantomData,
			switchover,
			transcript,
		}
	}
}

impl<'a, F, P, B, S, C> IntMulProver<'a, P, B, S, C>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	B: Bitwise,
	S: AsRef<[B]>,
	C: Challenger,
{
	/// Prove an integer multiplication statement.
	///
	/// This method consumes a `Witness` in order to reduce integer multiplication statement to
	/// evaluation claims on 1-bit multilinears. More formally:
	///  * `witness` contains po2-sized integer arrays  `a`, `b`, `c_lo` and `c_hi` that satisfy `a
	///    * b = c_lo | c_hi << (1 << log_bits)`, as well as the layers of the constant- and
	///      variable-base GKR product check circuits
	///  * The proving consists of five phases:
	///    - Phase 1: GKR tree roots for B & C are evaluated at a sampled point, after which
	///      reductions are performed to obtain evaluation claims on $(b * (G^{a_i} - 1) + 1)^{2^i}$
	///    - Phase 2: Frobenius twist is applied to obtain claims on $b * (G^{a_i} - 1) + 1$
	///    - Phase 3: Two batched sumchecks:
	///      - Selector mlecheck to reduce claims on $b * (G^{a_i} - 1) + 1$ to claims on $G^{a_i}$
	///        and $b$
	///      - First layer of GPA reduction for the `c_lo || c_hi` combined `c` tree
	///    - Phase 4: Batching all but last layers and `a`, `c_lo` and `c_hi`
	///    - Phase 5: Proving the last (widest) layers of `a`, `c_lo` and `c_hi` batched with
	///      rerandomization degree-1 mlecheck on `b` evaluations from phase 3
	///
	/// The output of this protocol is a set of evaluation claims on the `b` selectors representing
	/// all of `a`, `b`, `c_lo` and `c_hi` as column-major bit matrices, at a common evaluation
	/// point.
	pub fn prove(&mut self, witness: Witness<P, B, S>) -> Result<IntMulOutput<F>, Error> {
		let Witness {
			a,
			b,
			c_lo,
			c_hi,
			c_root,
		} = witness;

		let (n_vars, log_bits) = (c_root.log_len(), a.log_bits());
		assert!(log_bits >= 1);

		let initial_eval_point = self.transcript.sample_vec(n_vars);

		let (b_exponents, b_root, b_layers) = b.split();

		let b_eval = evaluate(&b_root, &initial_eval_point)?;
		let c_eval = evaluate(&c_root, &initial_eval_point)?;

		let mut writer = self.transcript.message();
		writer.write_scalar(b_eval);
		writer.write_scalar(c_eval);

		// Phase 1
		let Phase1Output {
			eval_point: phase1_eval_point,
			b_leaves_evals,
		} = self.phase1(log_bits, &initial_eval_point, (b_eval, b_layers.into_iter()))?;

		// Phase 2
		let Phase2Output { twisted_claims } =
			frobenius_twist(log_bits, &phase1_eval_point, &b_leaves_evals);

		// Splitting
		let (_, a_root, mut a_layers) = a.split();
		let (_, c_lo_root, mut c_lo_layers) = c_lo.split();
		let (_, c_hi_root, mut c_hi_layers) = c_hi.split();

		let a_last_layer = a_layers.pop().expect("log_bits >= 1");
		let c_lo_last_layer = c_lo_layers.pop().expect("log_bits >= 1");
		let c_hi_last_layer = c_hi_layers.pop().expect("log_bits >= 1");

		// Phase 3
		let Phase3Output {
			eval_point: phase3_eval_point,
			b_exponent_evals,
			selector_eval,
			c_lo_root_eval,
			c_hi_root_eval,
		} = self.phase3(
			log_bits,
			&twisted_claims,
			a_root,
			b_exponents.as_ref(),
			[c_lo_root, c_hi_root],
			&initial_eval_point,
			c_eval,
		)?;

		// Phase 4
		let Phase4Output {
			eval_point: phase4_eval_point,
			a_evals,
			c_lo_evals,
			c_hi_evals,
		} = self.phase4(
			log_bits,
			&phase3_eval_point,
			(selector_eval, a_layers.into_iter()),
			(c_lo_root_eval, c_lo_layers.into_iter()),
			(c_hi_root_eval, c_hi_layers.into_iter()),
		)?;

		// Phase 5
		let Phase5Output {
			eval_point: phase5_eval_point,
			scaled_a_c_exponent_evals,
			b_exponent_evals,
		} = self.phase5(
			log_bits,
			&phase4_eval_point,
			(&a_evals, a_last_layer),
			(&c_lo_evals, c_lo_last_layer),
			(&c_hi_evals, c_hi_last_layer),
			b_exponents.as_ref(),
			&phase3_eval_point,
			&b_exponent_evals,
		)?;

		let [a_exponent_evals, c_lo_exponent_evals, c_hi_exponent_evals] =
			normalize_a_c_exponent_evals(log_bits, scaled_a_c_exponent_evals);

		// Phase 6
		let z_challenge: F = self.transcript.sample();
		let subspace = BinarySubspace::<F>::with_dim(LOG_WORD_SIZE_BITS)?;
		let l_tilde = lagrange_evals(&subspace, z_challenge);
		assert_eq!(l_tilde.len(), a_exponent_evals.len());

		let make_final_claim = |evals| izip!(evals, &l_tilde).map(|(x, y)| x * y).sum();

		Ok(IntMulOutput {
			z_challenge,
			eval_point: phase5_eval_point,
			a_eval: make_final_claim(a_exponent_evals),
			b_eval: make_final_claim(b_exponent_evals),
			c_lo_eval: make_final_claim(c_lo_exponent_evals),
			c_hi_eval: make_final_claim(c_hi_exponent_evals),
		})
	}

	fn phase1(
		&mut self,
		log_bits: usize,
		eval_point: &[F],
		(b_root_eval, b_layers): (F, impl ExactSizeIterator<Item = Vec<FieldBuffer<P>>>),
	) -> Result<Phase1Output<F>, Error> {
		assert_eq!(b_layers.len(), log_bits);
		let mut eval_point = eval_point.to_vec();
		let mut evals = vec![b_root_eval];

		for (depth, layer) in b_layers.enumerate() {
			assert_eq!(evals.len(), 1 << depth);
			assert_eq!(layer.len(), 2 << depth);

			let a_sumcheck_prover =
				BivariateProductMultiMlecheckProver::new(make_pairs(layer), &eval_point, &evals)?;

			let a_prover = MleToSumCheckDecorator::new(a_sumcheck_prover);

			let BatchSumcheckOutput {
				challenges,
				mut multilinear_evals,
			} = batch_prove(vec![a_prover], self.transcript)?;

			assert_eq!(multilinear_evals.len(), 1);

			eval_point = challenges;
			evals = multilinear_evals
				.pop()
				.expect("multilinear_evals.len() == 1");
		}

		assert_eq!(evals.len(), 1 << log_bits);

		Ok(Phase1Output {
			eval_point,
			b_leaves_evals: evals,
		})
	}

	#[allow(clippy::too_many_arguments)]
	fn phase3(
		&mut self,
		log_bits: usize,
		twisted_claims: &[(Vec<F>, F)],
		selector: FieldBuffer<P>,
		b_exponents: &[B],
		c_lo_hi_roots: [FieldBuffer<P>; 2],
		c_eval_point: &[F],
		c_root_eval: F,
	) -> Result<Phase3Output<F>, Error> {
		let n_vars = selector.log_len();
		assert!(
			twisted_claims
				.iter()
				.all(|(point, _)| point.len() == n_vars)
		);
		assert_eq!(b_exponents.len(), 1 << n_vars);

		let selector_claims = twisted_claims
			.iter()
			.map(|&(ref point, value)| Claim {
				point: point.clone(),
				value,
			})
			.collect();

		let selector_prover =
			SelectorMlecheckProver::new(selector, selector_claims, b_exponents, self.switchover)?;

		let c_root_sumcheck_prover =
			BivariateProductMlecheckProver::new(c_lo_hi_roots, c_eval_point, c_root_eval)?;

		let c_root_prover = MleToSumCheckDecorator::new(c_root_sumcheck_prover);

		let provers = vec![Either::Left(selector_prover), Either::Right(c_root_prover)];
		let BatchSumcheckOutput {
			challenges,
			mut multilinear_evals,
		} = batch_prove(provers, self.transcript)?;

		assert_eq!(multilinear_evals.len(), 2);
		let c_root_prover_evals = multilinear_evals
			.pop()
			.expect("multilinear_evals.len() == 2");
		let selector_prover_evals = multilinear_evals
			.pop()
			.expect("multilinear_evals.len() == 2");

		Ok(make_phase_3_output(log_bits, &challenges, &selector_prover_evals, &c_root_prover_evals))
	}

	fn phase4(
		&mut self,
		log_bits: usize,
		eval_point: &[F],
		(a_root_eval, a_layers): (F, impl ExactSizeIterator<Item = Vec<FieldBuffer<P>>>),
		(c_lo_root_eval, c_lo_layers): (F, impl ExactSizeIterator<Item = Vec<FieldBuffer<P>>>),
		(c_hi_root_eval, c_hi_layers): (F, impl ExactSizeIterator<Item = Vec<FieldBuffer<P>>>),
	) -> Result<Phase4Output<F>, Error> {
		assert_eq!(a_layers.len(), log_bits - 1);
		assert_eq!(c_lo_layers.len(), log_bits - 1);
		assert_eq!(c_hi_layers.len(), log_bits - 1);

		let mut eval_point = eval_point.to_vec();
		let mut evals = vec![a_root_eval, c_lo_root_eval, c_hi_root_eval];

		for (depth, (a_l, c_lo_l, c_hi_l)) in izip!(a_layers, c_lo_layers, c_hi_layers).enumerate()
		{
			assert_eq!(a_l.len(), 2 << depth);
			assert_eq!(c_lo_l.len(), 2 << depth);
			assert_eq!(c_hi_l.len(), 2 << depth);
			assert_eq!(evals.len(), 3 << depth);

			let layer = [a_l, c_lo_l, c_hi_l].concat();
			let sumcheck_prover =
				BivariateProductMultiMlecheckProver::new(make_pairs(layer), &eval_point, &evals)?;

			let prover = MleToSumCheckDecorator::new(sumcheck_prover);

			let BatchSumcheckOutput {
				challenges,
				mut multilinear_evals,
			} = batch_prove(vec![prover], self.transcript)?;

			assert_eq!(multilinear_evals.len(), 1);
			eval_point = challenges;
			evals = multilinear_evals
				.pop()
				.expect("multilinear_evals.len() == 1");
		}

		debug_assert_eq!(evals.len(), 3 << (log_bits - 1));
		let c_hi_evals = evals.split_off(2 << (log_bits - 1));
		let c_lo_evals = evals.split_off(1 << (log_bits - 1));
		let a_evals = evals;

		Ok(Phase4Output {
			eval_point,
			a_evals,
			c_lo_evals,
			c_hi_evals,
		})
	}

	#[allow(clippy::too_many_arguments)]
	fn phase5(
		&mut self,
		log_bits: usize,
		a_c_eval_point: &[F],
		(a_evals, a_layer): (&[F], Vec<FieldBuffer<P>>),
		(c_lo_evals, c_lo_layer): (&[F], Vec<FieldBuffer<P>>),
		(c_hi_evals, c_hi_layer): (&[F], Vec<FieldBuffer<P>>),
		b_exponents: &[B],
		b_eval_point: &[F],
		b_exponent_evals: &[F],
	) -> Result<Phase5Output<F>, Error> {
		assert!(log_bits >= 1);
		assert_eq!(1 << log_bits, a_layer.len());
		assert_eq!(2 * a_evals.len(), a_layer.len());
		assert_eq!(2 * c_lo_evals.len(), c_lo_layer.len());
		assert_eq!(2 * c_hi_evals.len(), c_hi_layer.len());
		assert_eq!(b_eval_point.len(), a_layer.first().expect("log_bits >= 1").log_len());
		assert_eq!(a_c_eval_point.len(), b_eval_point.len());

		let layer = [a_layer, c_lo_layer, c_hi_layer].concat();
		let evals = [a_evals, c_lo_evals, c_hi_evals].concat();

		let a_c_sumcheck_prover =
			BivariateProductMultiMlecheckProver::new(make_pairs(layer), a_c_eval_point, &evals)?;

		let a_c_prover = MleToSumCheckDecorator::new(a_c_sumcheck_prover);

		assert_eq!(b_exponents.len(), 1 << b_eval_point.len());
		assert_eq!(b_exponent_evals.len(), 1 << log_bits);

		let b_sumcheck_prover = RerandMlecheckProver::<P, _>::new(
			b_eval_point,
			b_exponent_evals,
			b_exponents,
			self.switchover,
		)?;

		let b_prover = MleToSumCheckDecorator::new(b_sumcheck_prover);

		let BatchSumcheckOutput {
			challenges,
			mut multilinear_evals,
		} = batch_prove(vec![Either::Left(a_c_prover), Either::Right(b_prover)], self.transcript)?;

		assert_eq!(multilinear_evals.len(), 2);
		let b_prover_evals = multilinear_evals
			.pop()
			.expect("multilinear_evals.len() == 2");
		let a_c_prover_evals = multilinear_evals
			.pop()
			.expect("multilinear_evals.len() == 2");

		assert_eq!(a_c_prover_evals.len(), 3 << log_bits);
		assert_eq!(b_prover_evals.len(), 1 << log_bits);

		Ok(Phase5Output {
			eval_point: challenges,
			scaled_a_c_exponent_evals: a_c_prover_evals,
			b_exponent_evals: b_prover_evals,
		})
	}
}

fn make_pairs<T>(layer: Vec<T>) -> Vec<[T; 2]> {
	layer
		.into_iter()
		.chunks(2)
		.into_iter()
		.map(|chunk| chunk.collect_array().expect("chunk.len() == 2"))
		.collect()
}
