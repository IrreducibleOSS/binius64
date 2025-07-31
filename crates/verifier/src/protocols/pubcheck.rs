use std::iter;

use binius_field::Field;
use binius_transcript::{VerifierTranscript, fiat_shamir::Challenger};

use crate::{
	error::Error,
	protocols::{mlecheck, sumcheck::SumcheckOutput},
};

/// Output of [`verify`].
#[derive(Debug)]
pub struct VerifyOutput<F: Field> {
	/// Reduced evaluation claim on the witness multilinear at the challenge point.
	pub witness_eval: F,
	/// Reduced evaluation claim on the public multilinear at a prefix of the challenge point.
	pub public_eval: F,
	/// Evaluation point from the MLE-check.
	pub eval_point: Vec<F>,
}

/// Verify the public input check (pubcheck) protocol.
///
/// The pubcheck protocol argues that the witness multilinear agrees with the public input
/// multilinear on a subdomain. The witness $w$ is $\ell$-variate, and the public multilinear $p$
/// is $m$-variate, where $m \le \ell$. The interactive reduction argues that for all $v \in B_m$
///
/// $$
/// w(v_0, \ldots, v_{m-1}, 0^{\ell - m}) = p(v_0, \ldots, v_{m-1})
/// $$
///
/// The protocol is a zerocheck on the multilinear $w - p$, using a truncated challenge point. It
/// begins with an $m$-dimensional challenge point $r$ and reduces to an MLE-check that
/// $(w - p)(r || 0) = 0$.
///
/// ## Arguments
///
/// * `n_witness_vars` - base-2 logarithm of the number of witness words
/// * `challenge` - the $m$-dimensional challenge point
/// * `transcript` - the verifier's transcript
///
/// ## Preconditions
///
/// * `challenge.len()` is at most `n_witness_vars`
pub fn verify<F: Field, Challenger_: Challenger>(
	n_witness_vars: usize,
	challenge: &[F],
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<VerifyOutput<F>, Error> {
	let n_public_vars = challenge.len();
	assert!(n_public_vars <= n_witness_vars); // precondition

	// The MLE-check verifier checks an evaluation at the zero-padded point.
	let zero_padded_eval_point = itertools::chain(challenge.iter().copied(), iter::repeat(F::ZERO))
		.take(n_witness_vars)
		.collect::<Vec<_>>();

	let SumcheckOutput {
		eval,
		mut challenges,
	} = mlecheck::verify(
		&zero_padded_eval_point,
		1, // degree 1 for multilinear evaluation of (w - p)
		F::ZERO,
		transcript,
	)?;

	// MLE-check expects prover to bind variables high-to-low, so reverse challenge order.
	challenges.reverse();

	// Read the witness evaluation w(r_z, r_y').
	let witness_eval = transcript.message().read::<F>()?;

	// Derive the expected public evaluation
	let public_eval = witness_eval - eval;

	Ok(VerifyOutput {
		witness_eval,
		public_eval,
		eval_point: challenges,
	})
}
