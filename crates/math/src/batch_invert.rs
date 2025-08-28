// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField128bGhash as Ghash, Field};

/// Efficiently inverts multiple field elements simultaneously using Montgomery's batch inversion
/// trick.
///
/// This function implements a binary tree approach to batch field inversion, which is significantly
/// more efficient than inverting each element individually when dealing with many elements.
///
/// # Algorithm Overview
/// 1. **Product Tree Construction**: Build a binary tree bottom-up where leaves are input elements
///    and each internal node stores the product of its children using linear addressing
/// 2. **Root Inversion**: Perform single expensive field inversion on the root (product of all
///    elements)
/// 3. **Inverse Propagation**: Propagate the root inverse down through tree levels to compute
///    individual element inverses
///
/// # Performance Benefits
/// - **Single inversion**: Only one expensive field inversion instead of N inversions
/// - **Linear addressing**: Simple addition-based indexing for better cache locality
/// - **Zero handling**: Graceful handling of zero elements without division-by-zero errors
///
/// # Parameters
/// - `elements`: Array of field elements to invert (modified in-place)
/// - `scratchpad`: Working memory buffer, must be at least `2*N-1` elements
///
/// # Requirements
/// - `N` must be a power of 2 and ≥ 2
/// - `scratchpad.len() >= 2*N-1` for intermediate computations
#[inline]
pub fn batch_invert<const N: usize>(elements: &mut [Ghash], scratchpad: &mut [Ghash]) {
	assert!(N.is_power_of_two() && N >= 2, "N must be a power of 2 and >= 2");
	assert_eq!(elements.len(), N);
	assert!(scratchpad.len() >= 2 * N - 1, "scratchpad too small");

	let zero = Ghash::ZERO;
	let one = Ghash::ONE;
	let levels = N.ilog2() as usize;

	// Phase 1: Setup - Copy input elements, replacing zeros with ones
	// This prevents division-by-zero while preserving zero semantics in final output
	for i in 0..N {
		scratchpad[i] = if elements[i] == zero {
			one // Temporary replacement - restored to zero in final phase
		} else {
			elements[i]
		};
	}

	// Phase 2: Build product tree bottom-up using linear addressing
	// Each level combines pairs from the previous level into products
	let mut dest_offset = N; // Current write position in scratchpad

	// Build intermediate tree levels (N/2, N/4, N/8, ... down to 2 elements)
	for level in 1..levels {
		let level_size = N >> level; // Number of products at this level
		let src_offset = dest_offset - (level_size * 2); // Read from previous level

		// Combine adjacent pairs: scratchpad[2*i] * scratchpad[2*i+1]
		for i in 0..level_size {
			scratchpad[dest_offset + i] =
				scratchpad[src_offset + 2 * i] * scratchpad[src_offset + 2 * i + 1];
		}
		dest_offset += level_size; // Move to next level's storage
	}

	// Final level: multiply the last two products to get root
	let src_offset = dest_offset - 2;
	scratchpad[dest_offset] = scratchpad[src_offset] * scratchpad[src_offset + 1];

	// Phase 3: Invert root product (Montgomery's key insight: single inversion)
	scratchpad[dest_offset] = scratchpad[dest_offset]
		.invert()
		.expect("factors are non-zero, so product is non-zero");

	// Phase 4: Propagate inverse down tree levels (reverse order)
	// Each level computes inverses from the level above
	for level in 1..levels {
		let level_size = 1 << level; // Size doubles each level going down
		let src_offset = dest_offset; // Read from current position
		dest_offset -= level_size; // Move down to previous level

		// For each pair, compute inverses using: inv(a*b) * b = inv(a), inv(a*b) * a = inv(b)
		for i in 0..level_size >> 1 {
			let left_product = scratchpad[dest_offset + 2 * i]; // Original product a
			scratchpad[dest_offset + 2 * i] =
				scratchpad[dest_offset + 2 * i + 1] * scratchpad[src_offset + i]; // inv(a) = b * inv(a*b)
			scratchpad[dest_offset + 2 * i + 1] = left_product * scratchpad[src_offset + i]; // inv(b) = a * inv(a*b)
		}
	}

	// Phase 5: Extract final inverses and restore zero semantics
	// The last layer of products could be done in the loop immediately above,
	// but for speed we avoid an extra copy by merging it copying from the
	// scratchpad.
	for i in 0..N / 2 {
		let j = 2 * i;
		// Restore original zeros (marked in Phase 1)
		elements[j] = if elements[j] == zero {
			zero
		} else {
			scratchpad[j + 1] * scratchpad[dest_offset + i]
		};
		elements[j + 1] = if elements[j + 1] == zero {
			zero
		} else {
			scratchpad[j] * scratchpad[dest_offset + i]
		};
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{Field, Random, arithmetic_traits::InvertOrZero};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;

	fn test_batch_invert_for_size<const N: usize>(rng: &mut StdRng) {
		let mut state = [Ghash::ZERO; N];
		for i in 0..N {
			state[i] = if rng.random::<bool>() {
				Ghash::ZERO
			} else {
				Ghash::random(&mut *rng)
			};
		}

		let expected: [Ghash; N] = state.map(|x| x.invert_or_zero());

		let mut scratchpad = vec![Ghash::ZERO; 2 * N - 1];
		batch_invert::<N>(&mut state, &mut scratchpad);

		assert_eq!(state, expected);
	}

	#[test]
	fn test_batch_invert() {
		let mut rng = StdRng::seed_from_u64(0);

		for _ in 0..4 {
			test_batch_invert_for_size::<2>(&mut rng);
			test_batch_invert_for_size::<4>(&mut rng);
			test_batch_invert_for_size::<8>(&mut rng);
			test_batch_invert_for_size::<16>(&mut rng);
			test_batch_invert_for_size::<32>(&mut rng);
			test_batch_invert_for_size::<64>(&mut rng);
			test_batch_invert_for_size::<128>(&mut rng);
			test_batch_invert_for_size::<256>(&mut rng);
		}
	}
}
