use binius_field::{BinaryField, BinaryField128b, PackedBinaryField2x128b};

use super::{execute::ProverData, *};

type F = BinaryField128b;
type P = PackedBinaryField2x128b;

use binius_transcript::{ProverTranscript, fiat_shamir::HasherChallenger};
use blake2::Blake2b;
use digest::consts::U32;
type Blake2b256 = Blake2b<U32>;

#[test]
fn test_go() {
	let generator = F::MULTIPLICATIVE_GENERATOR;

	let a_exponent: u64 = 2;
	let b_exponent: u64 = 3;
	let c_lo_exponent: u64 = 6; // 2*3 = 6
	let c_hi_exponent: u64 = 0; // no high bits

	let a_exponents = vec![a_exponent];
	let b_exponents = vec![b_exponent];
	let c_lo_exponents = vec![c_lo_exponent];
	let c_hi_exponents = vec![c_hi_exponent];

	let ProverData {
		n_vars: _,
		a_exponents: _,
		b_exponents: _,
		c_lo_exponents: _,
		c_hi_exponents: _,
		a_layers,
		b_layers,
		c_layers,
	} = super::execute::execute::<P>(
		generator,
		&a_exponents,
		&b_exponents,
		&c_lo_exponents,
		&c_hi_exponents,
	)
	.unwrap();

	let mut prover_transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::default();

	let _prove_output = super::prove::prove::<F, P, HasherChallenger<Blake2b256>>(
		0,
		&b_exponents,
		a_layers.into_iter(),
		b_layers.into_iter(),
		c_layers.into_iter(),
		generator,
		&mut prover_transcript,
	);
}

#[test]
fn test_go_multiple() {
	use rand::Rng;

	let mut rng = rand::rng();

	let generator = F::MULTIPLICATIVE_GENERATOR;

	const NUM_EXPONENTS: usize = 1 << 5;
	let mut a_exponents = Vec::with_capacity(NUM_EXPONENTS);
	let mut b_exponents = Vec::with_capacity(NUM_EXPONENTS);
	let mut c_lo_exponents = Vec::with_capacity(NUM_EXPONENTS);
	let mut c_hi_exponents = Vec::with_capacity(NUM_EXPONENTS);

	for _ in 0..NUM_EXPONENTS {
		let a_exp = rng.random_range(1..u64::MAX);
		let b_exp = rng.random_range(1..u64::MAX);

		let a_u128 = a_exp as u128;
		let b_u128 = b_exp as u128;
		let full_result = a_u128 * b_u128;

		let c_lo = full_result as u64;
		let c_hi = (full_result >> 64) as u64;

		a_exponents.push(a_exp);
		b_exponents.push(b_exp);
		c_lo_exponents.push(c_lo);
		c_hi_exponents.push(c_hi);
	}

	let ProverData {
		n_vars,
		a_exponents: _,
		b_exponents: _,
		c_lo_exponents: _,
		c_hi_exponents: _,
		a_layers,
		b_layers,
		c_layers,
	} = execute::execute::<P>(generator, &a_exponents, &b_exponents, &c_lo_exponents, &c_hi_exponents)
		.unwrap();

	let mut prover_transcript = ProverTranscript::<HasherChallenger<Blake2b256>>::default();

	let _prove_output = prove::prove::<F, P, HasherChallenger<Blake2b256>>(
		n_vars,
		&b_exponents,
		a_layers.into_iter(),
		b_layers.into_iter(),
		c_layers.into_iter(),
		generator,
		&mut prover_transcript,
	);

	let mut verifier_transcript = prover_transcript.into_verifier();
	binius_verifier::protocols::intmul::verify::verify::<F, P, HasherChallenger<Blake2b256>>(
		n_vars,
		generator,
		&mut verifier_transcript,
	)
	.unwrap();
}
