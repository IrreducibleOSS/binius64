// Copyright 2025 Irreducible Inc.

use std::iter::repeat_with;

use binius_field::Field;
use rand::RngCore;

/// Generates a vector of random field elements.
///
/// # Arguments
///
/// * `rng` - Random number generator implementing RngCore
/// * `n` - Number of random field elements to generate
///
/// # Returns
///
/// Vector containing n random field elements
pub fn random_scalars<F: Field>(mut rng: impl RngCore, n: usize) -> Vec<F> {
	repeat_with(|| F::random(&mut rng)).take(n).collect()
}

#[cfg(test)]
mod tests {
	use binius_field::BinaryField32b;
	use proptest::prelude::*;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;

	proptest! {
		#[test]
		fn same_seed_produces_identical_results(
			seed: u64,
			n in 0..100usize
		) {
			let mut rng1 = StdRng::seed_from_u64(seed);
			let mut rng2 = StdRng::seed_from_u64(seed);

			let scalars1 = random_scalars::<BinaryField32b>(&mut rng1, n);
			let scalars2 = random_scalars::<BinaryField32b>(&mut rng2, n);

			prop_assert_eq!(scalars1, scalars2);
		}

		#[test]
		fn different_seeds_produce_different_results(seed1: u64, seed2: u64) {
			prop_assume!(seed1 != seed2);

			// Test with 10 elements - collision probability is 1/2^320 ≈ 10^-96
			let n = 10;

			let mut rng1 = StdRng::seed_from_u64(seed1);
			let mut rng2 = StdRng::seed_from_u64(seed2);

			let scalars1 = random_scalars::<BinaryField32b>(&mut rng1, n);
			let scalars2 = random_scalars::<BinaryField32b>(&mut rng2, n);

			prop_assert_ne!(scalars1, scalars2);
		}
	}
}
