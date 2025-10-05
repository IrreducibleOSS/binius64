// Copyright 2025 Irreducible Inc.

use binius_field::Field;

/// Computes the multilinear extension of the logical left shift indicator at a point.
///
/// The shift indicator for logical left shift (SLL) evaluates to 1 when bit `i` of the output
/// equals bit `j` of the input after shifting left by `s` positions. Specifically:
/// - `sll_ind(i, j, s) = 1` if and only if `i = j + s` and `i < 2^k`
/// - `sll_ind(i, j, s) = 0` otherwise
///
/// This function evaluates the multilinear extension of this indicator at the given point
/// `(i, j, s)` where each coordinate is a field element.
///
/// # Arguments
/// * `i` - Slice of field elements representing the output bit position (length k)
/// * `j` - Slice of field elements representing the input bit position (length k)
/// * `s` - Slice of field elements representing the shift amount (length k)
///
/// # Panics
/// Panics if the slices don't all have the same length.
pub fn sll_ind<F: Field>(i: &[F], j: &[F], s: &[F]) -> F {
	assert_eq!(i.len(), j.len(), "i and j must have the same length");
	assert_eq!(i.len(), s.len(), "i and s must have the same length");

	todo!("Implement sll_ind")
}

/// Computes the multilinear extension of the logical right shift indicator at a point.
///
/// The shift indicator for logical right shift (srl) evaluates to 1 when bit `i` of the output
/// equals bit `j` of the input after shifting right by `s` positions. Specifically:
/// - `srl_ind(i, j, s) = 1` if and only if `j = i + s` and `j < 2^k`
/// - `srl_ind(i, j, s) = 0` otherwise
///
/// This function evaluates the multilinear extension of this indicator at the given point
/// `(i, j, s)` where each coordinate is a field element.
///
/// # Arguments
/// * `i` - Slice of field elements representing the output bit position (length k)
/// * `j` - Slice of field elements representing the input bit position (length k)
/// * `s` - Slice of field elements representing the shift amount (length k)
///
/// # Panics
/// Panics if the slices don't all have the same length.
pub fn srl_ind<F: Field>(i: &[F], j: &[F], s: &[F]) -> F {
	assert_eq!(i.len(), j.len(), "i and j must have the same length");
	assert_eq!(i.len(), s.len(), "i and s must have the same length");

	todo!("Implement srl_ind")
}

/// Computes the multilinear extension of the arithmetic right shift indicator at a point.
///
/// The shift indicator for arithmetic right shift (sra) behaves like logical right shift,
/// but propagates the sign bit (bit 2^k - 1) for positions shifted beyond the original value.
/// Specifically:
/// - `sra_ind(i, j, s) = srl_ind(i, j, s)` for normal shifted bits
/// - Additionally, `sra_ind(i, 2^k - 1, s) = 1` for `i >= 2^k - s` (sign extension)
///
/// This function evaluates the multilinear extension of this indicator at the given point
/// `(i, j, s)` where each coordinate is a field element.
///
/// # Arguments
/// * `i` - Slice of field elements representing the output bit position (length k)
/// * `j` - Slice of field elements representing the input bit position (length k)
/// * `s` - Slice of field elements representing the shift amount (length k)
///
/// # Panics
/// Panics if the slices don't all have the same length.
pub fn sra_ind<F: Field>(i: &[F], j: &[F], s: &[F]) -> F {
	assert_eq!(i.len(), j.len(), "i and j must have the same length");
	assert_eq!(i.len(), s.len(), "i and s must have the same length");

	todo!("Implement sra_ind")
}

/// Computes the multilinear extension of the rotate right indicator at a point.
///
/// The shift indicator for rotate right (rotr) evaluates to 1 when bit `i` of the output
/// equals bit `j` of the input after rotating right by `s` positions. Unlike logical shifts,
/// bits that shift off one end wrap around to the other end. Specifically:
/// - `rotr_ind(i, j, s) = 1` if and only if `j = (i + s) mod 2^k`
/// - `rotr_ind(i, j, s) = 0` otherwise
///
/// This function evaluates the multilinear extension of this indicator at the given point
/// `(i, j, s)` where each coordinate is a field element.
///
/// # Arguments
/// * `i` - Slice of field elements representing the output bit position (length k)
/// * `j` - Slice of field elements representing the input bit position (length k)
/// * `s` - Slice of field elements representing the shift amount (length k)
///
/// # Panics
/// Panics if the slices don't all have the same length.
pub fn rotr_ind<F: Field>(i: &[F], j: &[F], s: &[F]) -> F {
	assert_eq!(i.len(), j.len(), "i and j must have the same length");
	assert_eq!(i.len(), s.len(), "i and s must have the same length");

	todo!("Implement rotr_ind")
}

#[cfg(test)]
mod tests {
	use proptest::prelude::*;
	use rand::{SeedableRng, rngs::StdRng};

	use super::*;
	use crate::{
		line::extrapolate_line_packed,
		test_utils::{B128, index_to_hypercube_point, random_scalars},
	};

	// Type alias for shift indicator functions
	type ShiftIndicatorFn<F> = fn(&[F], &[F], &[F]) -> F;

	// Helper to test hypercube evaluation for any shift indicator
	fn test_hypercube_evaluation<F: Field>(
		shift_fn: ShiftIndicatorFn<F>,
		i_idx: usize,
		j_idx: usize,
		s_idx: usize,
		expected_condition: bool,
	) {
		let i = index_to_hypercube_point::<F>(6, i_idx);
		let j = index_to_hypercube_point::<F>(6, j_idx);
		let s = index_to_hypercube_point::<F>(6, s_idx);

		let result = shift_fn(&i, &j, &s);
		let expected = if expected_condition { F::ONE } else { F::ZERO };
		assert_eq!(result, expected);
	}

	// Helper to test multilinearity of a function across all variables
	fn test_multilinearity<F: Field>(f: impl Fn(&[F]) -> F, num_vars: usize) {
		let mut rng = StdRng::seed_from_u64(0);

		// Generate random base point
		let mut point = random_scalars(&mut rng, num_vars);

		// Test linearity in each coordinate
		for coord_idx in 0..num_vars {
			let z = point[coord_idx];

			point[coord_idx] = F::ZERO;
			let y0 = f(&point);
			point[coord_idx] = F::ONE;
			let y1 = f(&point);

			point[coord_idx] = z;
			let yz = f(&point);

			// Check linearity using extrapolate_line_packed
			assert_eq!(yz, extrapolate_line_packed(y0, y1, z));
		}
	}

	// Test sll_ind on hypercube points
	proptest! {
		#[test]
		fn test_sll_ind_hypercube(
			i_idx in 0usize..64,
			j_idx in 0usize..64,
			s_idx in 0usize..64,
		) {
			test_hypercube_evaluation(
				sll_ind::<B128>,
				i_idx, j_idx, s_idx,
				i_idx == j_idx + s_idx
			);
		}
	}

	// Test srl_ind on hypercube points
	proptest! {
		#[test]
		fn test_srl_ind_hypercube(
			i_idx in 0usize..64,
			j_idx in 0usize..64,
			s_idx in 0usize..64,
		) {
			test_hypercube_evaluation(
				srl_ind::<B128>,
				i_idx, j_idx, s_idx,
				j_idx == i_idx + s_idx && j_idx < 64
			);
		}
	}

	// Test sra_ind on hypercube points
	proptest! {
		#[test]
		fn test_sra_ind_hypercube(
			i_idx in 0usize..64,
			j_idx in 0usize..64,
			s_idx in 0usize..64,
		) {
			// sra has two conditions: normal shift or sign extension
			let normal_shift = j_idx == i_idx + s_idx && j_idx < 64;
			let sign_extension = j_idx == 63 && s_idx > 0 && i_idx >= 64 - s_idx;

			test_hypercube_evaluation(
				sra_ind::<B128>,
				i_idx, j_idx, s_idx,
				normal_shift || sign_extension
			);
		}
	}

	// Test rotr_ind on hypercube points
	proptest! {
		#[test]
		fn test_rotr_ind_hypercube(
			i_idx in 0usize..64,
			j_idx in 0usize..64,
			s_idx in 0usize..64,
		) {
			test_hypercube_evaluation(
				rotr_ind::<B128>,
				i_idx, j_idx, s_idx,
				j_idx == (i_idx + s_idx) % 64
			);
		}
	}

	// Test multilinearity of all shift indicators
	#[test]
	fn test_shift_indicators_multilinearity() {
		let shift_inds: [ShiftIndicatorFn<B128>; 4] = [sll_ind, srl_ind, sra_ind, rotr_ind];
		for shift_fn in shift_inds {
			test_multilinearity(
				|v| {
					assert_eq!(v.len(), 9, "Expected 9 variables total");
					let i = &v[0..3];
					let j = &v[3..6];
					let s = &v[6..9];
					shift_fn(i, j, s)
				},
				9,
			);
		}
	}
}
