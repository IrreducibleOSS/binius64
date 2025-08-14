// Copyright 2025 Irreducible Inc.

use binius_field::{
	BinaryField128bGhash as Ghash, Field, WithUnderlier,
	byte_iteration::{ByteIteratorCallback, iterate_bytes},
};

use super::{
	constants::{B_FWD_COEFFS, B_INV_COEFFS, BYTES_PER_GHASH, M, ROUND_CONSTANTS},
	linear_tables::{LINEAR_B_FWD_TABLE, LINEAR_B_INV_TABLE},
};

fn batch_invert(state: &mut [Ghash; M]) {
	let x0 = state[0];
	let x1 = state[1];
	let x2 = state[2];
	let x3 = state[3];

	let zero = Ghash::ZERO;
	let one = Ghash::ONE;

	// Replace zeros with ones for Montgomery batch inversion, track which were zero
	let x0_nz = if x0 == zero { one } else { x0 };
	let x1_nz = if x1 == zero { one } else { x1 };
	let x2_nz = if x2 == zero { one } else { x2 };
	let x3_nz = if x3 == zero { one } else { x3 };

	// Montgomery batch inversion on non-zero values
	let left_product = x0_nz * x1_nz;
	let right_product = x2_nz * x3_nz;
	let root_product = left_product * right_product;
	let root_inv = root_product
		.invert()
		.expect("factors are non-zero, so product is non-zero");

	let left_inv = right_product * root_inv;
	let right_inv = left_product * root_inv;

	// Compute inverses, then mask zeros back to zero
	state[0] = if x0 == zero { zero } else { x1_nz * left_inv };
	state[1] = if x1 == zero { zero } else { x0_nz * left_inv };
	state[2] = if x2 == zero { zero } else { x3_nz * right_inv };
	state[3] = if x3 == zero { zero } else { x2_nz * right_inv };
}

pub fn linearized_transform_scalar(x: &mut Ghash, table: &'static [[Ghash; 256]; BYTES_PER_GHASH]) {
	struct TableCallback {
		table: &'static [[Ghash; 256]; BYTES_PER_GHASH],
		result: Ghash,
		byte_idx: usize,
	}

	impl ByteIteratorCallback for TableCallback {
		fn call(&mut self, iter: impl Iterator<Item = u8>) {
			iter.zip(self.table.iter()).for_each(|(byte, lookup)| {
				self.result += lookup[byte as usize];
			});
		}
	}

	let mut callback = TableCallback {
		table,
		result: Ghash::ZERO,
		byte_idx: 0,
	};
	iterate_bytes(std::slice::from_ref(x), &mut callback);
	*x = callback.result;
}

pub fn b_fwd_transform<const N: usize>(state: &mut [Ghash; N]) {
	(0..N).for_each(|i| {
		linearized_transform_scalar(&mut state[i], &LINEAR_B_FWD_TABLE);
		state[i] += B_FWD_COEFFS[0];
	});
}

pub fn b_inv_transform<const N: usize>(state: &mut [Ghash; N]) {
	(0..N).for_each(|i| {
		linearized_transform_scalar(&mut state[i], &LINEAR_B_INV_TABLE);
		state[i] += B_INV_COEFFS[0];
	});
}

pub fn sbox(state: &mut [Ghash; M], transform: impl Fn(&mut [Ghash; M])) {
	batch_invert(state);
	transform(state);
}

#[inline]
// This could be moved to the field crate
fn mul_x(a: Ghash) -> Ghash {
	let val = a.to_underlier();
	let shifted = val << 1;

	// GHASH irreducible polynomial: x^128 + x^7 + x^2 + x + 1
	// When the high bit is set, we need to XOR with the reduction polynomial 0x87
	// All 1s if the top bit is set, all 0s otherwise
	let mask = (val >> 127).wrapping_neg();
	let result = shifted ^ (0x87 & mask);

	Ghash::from_underlier(result)
}

pub fn mds_mul(a: &mut [Ghash; M]) {
	// a = [a0, a1, a2, a3]
	let sum = a[0] + a[1] + a[2] + a[3];
	let a0 = a[0];

	// 2*a0 + 3*a1 + a2 + a3
	a[0] += sum + mul_x(a[0] + a[1]);

	// a0 + 2*a1 + 3*a2 + a3
	a[1] += sum + mul_x(a[1] + a[2]);

	// a0 + a1 + 2*a2 + 3*a3
	a[2] += sum + mul_x(a[2] + a[3]);

	// 3*a0 + a1 + a2 + 2*a3
	a[3] += sum + mul_x(a[3] + a0);
}

pub fn constants_add(state: &mut [Ghash; M], constants: &[Ghash; M]) {
	for i in 0..M {
		state[i] += constants[i];
	}
}

fn round(state: &mut [Ghash; 4], round_constants_idx: usize) {
	// First half
	sbox(state, b_inv_transform);
	mds_mul(state);
	constants_add(state, &ROUND_CONSTANTS[round_constants_idx]);
	// // Second half
	sbox(state, b_fwd_transform);
	mds_mul(state);
	constants_add(state, &ROUND_CONSTANTS[round_constants_idx + 1]);
}

pub fn permutation(state: &mut [Ghash; M]) {
	constants_add(state, &ROUND_CONSTANTS[0]);
	for round_num in 0..8 {
		round(state, 1 + 2 * round_num);
	}
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_field::{Random, arithmetic_traits::InvertOrZero};
	use rand::{SeedableRng, rngs::StdRng};

	use super::{super::constants::matrix_mul, *};

	#[test]
	fn test_batch_invert() {
		let test_cases = [
			([1, 2, 3, 4], "all non-zero"),
			([0, 0, 0, 0], "all zeros"),
			([0, 2, 3, 4], "first zero"),
			([1, 0, 0, 4], "middle zeros"),
			([1, 0, 3, 0], "alternating"),
		];

		for (input, desc) in test_cases {
			let mut state: [Ghash; M] = input.map(Ghash::new);
			let expected: [Ghash; M] = input.map(|x| Ghash::new(x).invert_or_zero());

			batch_invert(&mut state);
			assert_eq!(state, expected, "{desc} case failed");
		}
	}

	#[test]
	fn test_mds() {
		let mut rng = StdRng::seed_from_u64(0);
		let input: [Ghash; M] = std::array::from_fn(|_| Ghash::random(&mut rng));

		let matrix: [Ghash; M * M] = [
			2, 3, 1, 1, //
			1, 2, 3, 1, //
			1, 1, 2, 3, //
			3, 1, 1, 2,
		]
		.map(Ghash::from_underlier);
		let expected = matrix_mul(&matrix, &input);

		let mut actual = input;
		mds_mul(&mut actual);

		assert_eq!(actual, expected);
	}

	#[test]
	fn test_permutation() {
		let mut rng = StdRng::seed_from_u64(0);
		// Outputs computed from a Sage script
		let cases = [
			(
				array::from_fn(|_| Ghash::new(0x0)),
				[
					Ghash::new(0x5e9a7b63d8d1a93953d56ceb6dcf6a35),
					Ghash::new(0xa3262c57f6cdd8c368639c1a4f01ab5a),
					Ghash::new(0x1dc99e37723063c4f178826d2a6802e3),
					Ghash::new(0xfdf935c9d9fae3d560a75026a049bf7c),
				],
			),
			(
				[
					Ghash::new(0xdeadbeef),
					Ghash::new(0x0),
					Ghash::new(0xdeadbeef),
					Ghash::new(0x0),
				],
				[
					Ghash::new(0x1d02eaf6cf48c108a2ae1d9e27812364),
					Ghash::new(0xc9bae4f4c782d46ed28245525f04fb3c),
					Ghash::new(0xf4fea518a1e62f97748266e86acac536),
					Ghash::new(0x22b25c68a52fef4b855f8862bdd418c4),
				],
			),
			(
				array::from_fn(|_| Ghash::random(&mut rng)),
				[
					Ghash::new(0xdd1c99b8f9f2ec20abf21f082a56c9f3),
					Ghash::new(0x3f5ec0a548673b571ba93d7751c98624),
					Ghash::new(0xe1c5c8fc8f4c80cfa8841cfd0ae0fbbb),
					Ghash::new(0xa054cc0d7379b474df8726cb448ca22b),
				],
			),
		];

		for (input, expected) in cases {
			let mut state = input;
			permutation(&mut state);
			assert_eq!(state, expected);
		}
	}
}
