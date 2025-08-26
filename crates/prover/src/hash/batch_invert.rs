// Copyright 2025 Irreducible Inc.

use binius_field::{BinaryField128bGhash as Ghash, Field};

/// Efficiently inverts multiple field elements simultaneously using Montgomery's batch inversion
/// trick.
///
/// This function implements a binary tree approach to batch field inversion, which is significantly
/// more efficient than inverting each element individually when dealing with many elements.
///
/// # Algorithm Overview
/// 1. **Product Tree Construction**: Build a binary tree where each leaf is an input element and
///    each internal node is the product of its children
/// 2. **Root Inversion**: Invert only the root (product of all elements)
/// 3. **Inverse Propagation**: Propagate the inverse down the tree to compute individual inverses
///
/// # Performance Benefits
/// - Single field inversion instead of N inversions (inversion is expensive)
/// - Tree structure maximizes instruction-level parallelism in multiplications
/// - Zero elements are handled gracefully without division-by-zero
///
/// # Parameters
/// - `elements`: Array of field elements to invert (modified in-place)
/// - `scratchpad`: Working memory buffer, must be at least `2*N-1` elements
///
/// # Requirements
/// - `N` must be a power of 2 and ≥ 2
/// - `scratchpad.len() >= 2*N-1` for intermediate computations
///
/// # Scratchpad Layout
/// ```
/// [0..N): Input elements (zeros replaced with ones)
/// [N..2N-1): Product tree levels (bottom-up)
/// ```
pub fn batch_invert_scratchpad_generic<const N: usize>(
	elements: &mut [Ghash; N],
	scratchpad: &mut [Ghash],
) {
	assert!(N.is_power_of_two() && N >= 2, "N must be a power of 2 and >= 2");
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

	// Phase 2: Build product tree bottom-up
	// Each level computes products of pairs from the previous level
	let mut dest_offset = N; // Points to current level's storage in scratchpad

	// Level 1: Pair up adjacent elements (N/2 products)
	// Each element at position i becomes product of elements at 2i and 2i+1
	if levels >= 2 {
		let level_size = N >> 1; // Number of products at this level
		let src_offset = dest_offset ^ (level_size << 1); // XOR for efficient offset calculation

		for i in 0..level_size {
			// Multiply adjacent pairs: scratchpad[2i] * scratchpad[2i+1]
			scratchpad[dest_offset ^ i] =
				scratchpad[src_offset ^ (i << 1)] * scratchpad[src_offset ^ (i << 1) ^ 1];
		}
		dest_offset += level_size;
	}

	// Level 2: Pair up level 1 products (N/4 products)
	if levels >= 3 {
		let level_size = N >> 2;
		let src_offset = dest_offset ^ (level_size << 1);

		for i in 0..level_size {
			scratchpad[dest_offset ^ i] =
				scratchpad[src_offset ^ (i << 1)] * scratchpad[src_offset ^ (i << 1) ^ 1];
		}
		dest_offset += level_size;
	}

	// Level 3: Continue building tree (N/8 products)
	if levels >= 4 {
		let level_size = N >> 3;
		let src_offset = dest_offset ^ (level_size << 1);

		for i in 0..level_size {
			scratchpad[dest_offset ^ i] =
				scratchpad[src_offset ^ (i << 1)] * scratchpad[src_offset ^ (i << 1) ^ 1];
		}
		dest_offset += level_size;
	}

	// Manually unroll level 4 (level_size = N/16)
	if levels >= 5 {
		let level_size = N >> 4;
		let src_offset = dest_offset ^ (N >> 3);

		for i in 0..level_size {
			scratchpad[dest_offset ^ i] =
				scratchpad[src_offset ^ (i << 1)] * scratchpad[src_offset ^ (i << 1) ^ 1];
		}
		dest_offset += level_size;
	}

	// Handle remaining larger levels with loop
	for level in 5..levels {
		let level_size = N >> level;
		let src_offset = dest_offset ^ (level_size << 1);

		for i in 0..level_size {
			scratchpad[dest_offset ^ i] =
				scratchpad[src_offset ^ (i << 1)] * scratchpad[src_offset ^ (i << 1) ^ 1];
		}
		dest_offset += level_size;
	}

	let src_offset = dest_offset ^ (1 << 1);
	scratchpad[dest_offset] = scratchpad[src_offset] * scratchpad[src_offset ^ 1];

	// Invert root product (Montgomery's key insight: single inversion)
	scratchpad[dest_offset] = scratchpad[dest_offset]
		.invert()
		.expect("factors are non-zero, so product is non-zero");

	// Phase 3: Propagate inverses down tree (unrolled for performance)
	// Level 1: size=2
	if levels >= 2 {
		let src_offset = dest_offset;
		dest_offset -= 2;

		let save = scratchpad[dest_offset];
		scratchpad[dest_offset] = scratchpad[dest_offset ^ 1] * scratchpad[src_offset];
		scratchpad[dest_offset ^ 1] = save * scratchpad[src_offset];
	}

	// Level 2: size=4
	if levels >= 3 {
		let src_offset = dest_offset;
		dest_offset -= 4;

		for i in 0..2 {
			let save = scratchpad[dest_offset ^ (i << 1)];
			scratchpad[dest_offset ^ (i << 1)] =
				scratchpad[dest_offset ^ (i << 1) ^ 1] * scratchpad[src_offset ^ i];
			scratchpad[dest_offset ^ (i << 1) ^ 1] = save * scratchpad[src_offset ^ i];
		}
	}

	// Level 3: size=8
	if levels >= 4 {
		let src_offset = dest_offset;
		dest_offset -= 8;

		for i in 0..4 {
			let save = scratchpad[dest_offset ^ (i << 1)];
			scratchpad[dest_offset ^ (i << 1)] =
				scratchpad[dest_offset ^ (i << 1) ^ 1] * scratchpad[src_offset ^ i];
			scratchpad[dest_offset ^ (i << 1) ^ 1] = save * scratchpad[src_offset ^ i];
		}
	}

	// Level 4: size=16
	if levels >= 5 {
		let src_offset = dest_offset;
		dest_offset -= 16;

		for i in 0..8 {
			let save = scratchpad[dest_offset ^ (i << 1)];
			scratchpad[dest_offset ^ (i << 1)] =
				scratchpad[dest_offset ^ (i << 1) ^ 1] * scratchpad[src_offset ^ i];
			scratchpad[dest_offset ^ (i << 1) ^ 1] = save * scratchpad[src_offset ^ i];
		}
	}

	// Dynamic levels: size=32,64,128,...
	for level in 5..levels {
		let level_size = 1 << level;
		let src_offset = dest_offset;
		dest_offset -= level_size;

		for i in 0..level_size >> 1 {
			let save = scratchpad[dest_offset ^ (i << 1)];
			scratchpad[dest_offset ^ (i << 1)] =
				scratchpad[dest_offset ^ (i << 1) ^ 1] * scratchpad[src_offset ^ i];
			scratchpad[dest_offset ^ (i << 1) ^ 1] = save * scratchpad[src_offset ^ i];
		}
	}

	// Final: compute inverses and restore zeros
	for i in 0..N >> 1 {
		let j = i << 1;
		elements[j] = if elements[j] == zero {
			zero
		} else {
			scratchpad[j ^ 1] * scratchpad[dest_offset ^ i]
		};
		elements[j ^ 1] = if elements[j ^ 1] == zero {
			zero
		} else {
			scratchpad[j] * scratchpad[dest_offset ^ i]
		};
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{Field, Random, arithmetic_traits::InvertOrZero};
	use rand::{Rng, SeedableRng, rngs::StdRng};

	use super::*;

	fn test_batch_invert_size<const N: usize>(rng: &mut StdRng) {
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
		batch_invert_scratchpad_generic::<N>(&mut state, &mut scratchpad);

		assert_eq!(state, expected);
	}

	#[test]
	fn test_batch_invert_scratchpad_generic() {
		let mut rng = StdRng::seed_from_u64(0);

		for _ in 0..4 {
			test_batch_invert_size::<2>(&mut rng);
			test_batch_invert_size::<4>(&mut rng);
			test_batch_invert_size::<8>(&mut rng);
			test_batch_invert_size::<16>(&mut rng);
			test_batch_invert_size::<32>(&mut rng);
			test_batch_invert_size::<64>(&mut rng);
			test_batch_invert_size::<128>(&mut rng);
			test_batch_invert_size::<256>(&mut rng);
		}
	}
}
