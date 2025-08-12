// Copyright 2025 Irreducible Inc.

use binius_field::{
	BinaryField128bGhash as Ghash, Field, WithUnderlier, arithmetic_traits::InvertOrZero,
};
use itertools::izip;
use std::ops::BitXor;

// INVERSION

#[inline]
pub fn batch_invert_4(state: &mut [Ghash; 4]) {
	let x0 = state[0];
	let x1 = state[1];
	let x2 = state[2];
	let x3 = state[3];

	let left_product = x0 * x1; // x0 * x1
	let right_product = x2 * x3; // x2 * x3

	let root_product = left_product * right_product; // (x0*x1) * (x2*x3)
	let root_inv = root_product.invert_or_zero();

	let left_inv = right_product * root_inv; // (x2*x3) * (x0*x1*x2*x3)^-1 = (x0*x1)^-1
	let right_inv = left_product * root_inv; // (x0*x1) * (x0*x1*x2*x3)^-1 = (x2*x3)^-1

	state[0] = x1 * left_inv; // x1 * (x0*x1)^-1 = x0^-1
	state[1] = x0 * left_inv; // x0 * (x0*x1)^-1 = x1^-1
	state[2] = x3 * right_inv; // x3 * (x2*x3)^-1 = x2^-1
	state[3] = x2 * right_inv; // x2 * (x2*x3)^-1 = x3^-1
}

#[inline]
pub fn batch_invert_4_owned(state: [Ghash; 4]) -> [Ghash; 4] {
	let x0 = state[0];
	let x1 = state[1];
	let x2 = state[2];
	let x3 = state[3];

	let left_product = x0 * x1; // x0 * x1
	let right_product = x2 * x3; // x2 * x3

	let root_product = left_product * right_product; // (x0*x1) * (x2*x3)
	let root_inv = root_product.invert_or_zero();

	let left_inv = right_product * root_inv; // (x2*x3) * (x0*x1*x2*x3)^-1 = (x0*x1)^-1
	let right_inv = left_product * root_inv; // (x0*x1) * (x0*x1*x2*x3)^-1 = (x2*x3)^-1

	let s0 = x1 * left_inv; // x1 * (x0*x1)^-1 = x0^-1
	let s1 = x0 * left_inv; // x0 * (x0*x1)^-1 = x1^-1
	let s2 = x3 * right_inv; // x3 * (x2*x3)^-1 = x2^-1
	let s3 = x2 * right_inv; // x2 * (x2*x3)^-1 = x3^-1
	[s0, s1, s2, s3]
}

#[inline]
pub fn batch_invert_8(state: &mut [Ghash; 8]) {
	let x0 = state[0];
	let x1 = state[1];
	let x2 = state[2];
	let x3 = state[3];
	let x4 = state[4];
	let x5 = state[5];
	let x6 = state[6];
	let x7 = state[7];

	// First level: pair products
	let p01 = x0 * x1; // x0 * x1
	let p23 = x2 * x3; // x2 * x3
	let p45 = x4 * x5; // x4 * x5
	let p67 = x6 * x7; // x6 * x7

	// Second level: quad products
	let left_quad = p01 * p23; // (x0*x1) * (x2*x3)
	let right_quad = p45 * p67; // (x4*x5) * (x6*x7)

	// Root product
	let root_product = left_quad * right_quad; // All 8 elements multiplied
	let root_inv = root_product.invert_or_zero();

	// Work backwards: quad inverses
	let left_quad_inv = right_quad * root_inv; // (x4*x5*x6*x7) * root_inv^-1 = (x0*x1*x2*x3)^-1
	let right_quad_inv = left_quad * root_inv; // (x0*x1*x2*x3) * root_inv^-1 = (x4*x5*x6*x7)^-1

	// Pair inverses
	let p01_inv = p23 * left_quad_inv; // (x2*x3) * (x0*x1*x2*x3)^-1 = (x0*x1)^-1
	let p23_inv = p01 * left_quad_inv; // (x0*x1) * (x0*x1*x2*x3)^-1 = (x2*x3)^-1
	let p45_inv = p67 * right_quad_inv; // (x6*x7) * (x4*x5*x6*x7)^-1 = (x4*x5)^-1
	let p67_inv = p45 * right_quad_inv; // (x4*x5) * (x4*x5*x6*x7)^-1 = (x6*x7)^-1

	// Individual element inverses
	state[0] = x1 * p01_inv; // x1 * (x0*x1)^-1 = x0^-1
	state[1] = x0 * p01_inv; // x0 * (x0*x1)^-1 = x1^-1
	state[2] = x3 * p23_inv; // x3 * (x2*x3)^-1 = x2^-1
	state[3] = x2 * p23_inv; // x2 * (x2*x3)^-1 = x3^-1
	state[4] = x5 * p45_inv; // x5 * (x4*x5)^-1 = x4^-1
	state[5] = x4 * p45_inv; // x4 * (x4*x5)^-1 = x5^-1
	state[6] = x7 * p67_inv; // x7 * (x6*x7)^-1 = x6^-1
	state[7] = x6 * p67_inv; // x6 * (x6*x7)^-1 = x7^-1
}

#[inline]
pub fn batch_invert_16(state: &mut [Ghash; 16]) {
	let x0 = state[0];
	let x1 = state[1];
	let x2 = state[2];
	let x3 = state[3];
	let x4 = state[4];
	let x5 = state[5];
	let x6 = state[6];
	let x7 = state[7];
	let x8 = state[8];
	let x9 = state[9];
	let x10 = state[10];
	let x11 = state[11];
	let x12 = state[12];
	let x13 = state[13];
	let x14 = state[14];
	let x15 = state[15];

	// Level 1: pair products (8 pairs)
	let p01 = x0 * x1;
	let p23 = x2 * x3;
	let p45 = x4 * x5;
	let p67 = x6 * x7;
	let p89 = x8 * x9;
	let p1011 = x10 * x11;
	let p1213 = x12 * x13;
	let p1415 = x14 * x15;

	// Level 2: quad products (4 quads)
	let q0123 = p01 * p23;
	let q4567 = p45 * p67;
	let q891011 = p89 * p1011;
	let q12131415 = p1213 * p1415;

	// Level 3: oct products (2 octs)
	let o01234567 = q0123 * q4567;
	let o89101112131415 = q891011 * q12131415;

	// Level 4: root product
	let root_product = o01234567 * o89101112131415;
	let root_inv = root_product.invert_or_zero();

	// Work backwards: oct inverses
	let o01234567_inv = o89101112131415 * root_inv;
	let o89101112131415_inv = o01234567 * root_inv;

	// Quad inverses
	let q0123_inv = q4567 * o01234567_inv;
	let q4567_inv = q0123 * o01234567_inv;
	let q891011_inv = q12131415 * o89101112131415_inv;
	let q12131415_inv = q891011 * o89101112131415_inv;

	// Pair inverses
	let p01_inv = p23 * q0123_inv;
	let p23_inv = p01 * q0123_inv;
	let p45_inv = p67 * q4567_inv;
	let p67_inv = p45 * q4567_inv;
	let p89_inv = p1011 * q891011_inv;
	let p1011_inv = p89 * q891011_inv;
	let p1213_inv = p1415 * q12131415_inv;
	let p1415_inv = p1213 * q12131415_inv;

	// Individual element inverses
	state[0] = x1 * p01_inv;
	state[1] = x0 * p01_inv;
	state[2] = x3 * p23_inv;
	state[3] = x2 * p23_inv;
	state[4] = x5 * p45_inv;
	state[5] = x4 * p45_inv;
	state[6] = x7 * p67_inv;
	state[7] = x6 * p67_inv;
	state[8] = x9 * p89_inv;
	state[9] = x8 * p89_inv;
	state[10] = x11 * p1011_inv;
	state[11] = x10 * p1011_inv;
	state[12] = x13 * p1213_inv;
	state[13] = x12 * p1213_inv;
	state[14] = x15 * p1415_inv;
	state[15] = x14 * p1415_inv;
}

#[inline]
pub fn batch_invert_32(state: &mut [Ghash; 32]) {
	// Load all 32 elements
	let x = [
		state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7], state[8],
		state[9], state[10], state[11], state[12], state[13], state[14], state[15], state[16],
		state[17], state[18], state[19], state[20], state[21], state[22], state[23], state[24],
		state[25], state[26], state[27], state[28], state[29], state[30], state[31],
	];

	// Level 1: 16 pair products (32 → 16)
	let p = [
		x[0] * x[1],
		x[2] * x[3],
		x[4] * x[5],
		x[6] * x[7],
		x[8] * x[9],
		x[10] * x[11],
		x[12] * x[13],
		x[14] * x[15],
		x[16] * x[17],
		x[18] * x[19],
		x[20] * x[21],
		x[22] * x[23],
		x[24] * x[25],
		x[26] * x[27],
		x[28] * x[29],
		x[30] * x[31],
	];

	// Level 2: 8 quad products (16 → 8)
	let q = [
		p[0] * p[1],
		p[2] * p[3],
		p[4] * p[5],
		p[6] * p[7],
		p[8] * p[9],
		p[10] * p[11],
		p[12] * p[13],
		p[14] * p[15],
	];

	// Level 3: 4 oct products (8 → 4)
	let o = [q[0] * q[1], q[2] * q[3], q[4] * q[5], q[6] * q[7]];

	// Level 4: 2 sixteen products (4 → 2)
	let s = [o[0] * o[1], o[2] * o[3]];

	// Level 5: 1 root product (2 → 1)
	let root = s[0] * s[1];
	let root_inv = root.invert_or_zero();

	// Work backwards: sixteen inverses
	let s_inv = [s[1] * root_inv, s[0] * root_inv];

	// Oct inverses
	let o_inv = [
		o[1] * s_inv[0],
		o[0] * s_inv[0],
		o[3] * s_inv[1],
		o[2] * s_inv[1],
	];

	// Quad inverses
	let q_inv = [
		q[1] * o_inv[0],
		q[0] * o_inv[0],
		q[3] * o_inv[1],
		q[2] * o_inv[1],
		q[5] * o_inv[2],
		q[4] * o_inv[2],
		q[7] * o_inv[3],
		q[6] * o_inv[3],
	];

	// Pair inverses
	let p_inv = [
		p[1] * q_inv[0],
		p[0] * q_inv[0],
		p[3] * q_inv[1],
		p[2] * q_inv[1],
		p[5] * q_inv[2],
		p[4] * q_inv[2],
		p[7] * q_inv[3],
		p[6] * q_inv[3],
		p[9] * q_inv[4],
		p[8] * q_inv[4],
		p[11] * q_inv[5],
		p[10] * q_inv[5],
		p[13] * q_inv[6],
		p[12] * q_inv[6],
		p[15] * q_inv[7],
		p[14] * q_inv[7],
	];

	// Individual element inverses
	state[0] = x[1] * p_inv[0];
	state[1] = x[0] * p_inv[0];
	state[2] = x[3] * p_inv[1];
	state[3] = x[2] * p_inv[1];
	state[4] = x[5] * p_inv[2];
	state[5] = x[4] * p_inv[2];
	state[6] = x[7] * p_inv[3];
	state[7] = x[6] * p_inv[3];
	state[8] = x[9] * p_inv[4];
	state[9] = x[8] * p_inv[4];
	state[10] = x[11] * p_inv[5];
	state[11] = x[10] * p_inv[5];
	state[12] = x[13] * p_inv[6];
	state[13] = x[12] * p_inv[6];
	state[14] = x[15] * p_inv[7];
	state[15] = x[14] * p_inv[7];
	state[16] = x[17] * p_inv[8];
	state[17] = x[16] * p_inv[8];
	state[18] = x[19] * p_inv[9];
	state[19] = x[18] * p_inv[9];
	state[20] = x[21] * p_inv[10];
	state[21] = x[20] * p_inv[10];
	state[22] = x[23] * p_inv[11];
	state[23] = x[22] * p_inv[11];
	state[24] = x[25] * p_inv[12];
	state[25] = x[24] * p_inv[12];
	state[26] = x[27] * p_inv[13];
	state[27] = x[26] * p_inv[13];
	state[28] = x[29] * p_inv[14];
	state[29] = x[28] * p_inv[14];
	state[30] = x[31] * p_inv[15];
	state[31] = x[30] * p_inv[15];
}

#[inline]
pub fn batch_invert_generic<const N: usize>(state: &mut [Ghash; N]) {
	assert!(N > 0 && N.is_power_of_two(), "N must be a positive power of 2");

	if N == 1 {
		state[0] = state[0]; // Would be state[0].invert_or_zero()
		return;
	}

	// Simple recursive approach using stack-allocated arrays
	batch_invert_recursive(state);
}

fn batch_invert_recursive(state: &mut [Ghash]) {
	if state.len() == 2 {
		// Base case: invert pair
		let a = state[0];
		let b = state[1];
		let product_inv = a * b; // Would be (a * b).invert_or_zero()
		state[0] = b * product_inv; // b * (a*b)^-1 = a^-1
		state[1] = a * product_inv; // a * (a*b)^-1 = b^-1
		return;
	}

	let half = state.len() / 2;
	let (left, right) = state.split_at_mut(half);

	// Recursively invert left and right halves
	batch_invert_recursive(left);
	batch_invert_recursive(right);

	// Compute products of each half
	let left_product = left.iter().fold(Ghash::ONE, |acc, &x| acc * x);
	let right_product = right.iter().fold(Ghash::ONE, |acc, &x| acc * x);

	// Invert the product of products
	let total_inv = left_product * right_product; // Would be (left_product * right_product).invert_or_zero()

	// Correct the inverses using cross-products
	let left_correction = right_product * total_inv;
	let right_correction = left_product * total_inv;

	for elem in left.iter_mut() {
		*elem = *elem * left_correction;
	}
	for elem in right.iter_mut() {
		*elem = *elem * right_correction;
	}
}

// LINEARIZED POLY

// Funny Claude-generated table
const fn generate_byte_table_entry(table_seed: u128, byte_index: usize, byte_value: usize) -> u128 {
	let seed = table_seed
		.wrapping_mul(0x9e3779b97f4a7c15)
		.wrapping_add((byte_index as u128).wrapping_mul(0x6c078965))
		.wrapping_add(byte_value as u128);
	let a = 0x5deece66d;
	let c = 0xb;
	let m = 1u128 << 48;

	let x1 = seed.wrapping_mul(a).wrapping_add(c) % m;
	let x2 = x1.wrapping_mul(a).wrapping_add(c) % m;
	let x3 = x2.wrapping_mul(a).wrapping_add(c) % m;

	(x1 << 80) | (x2 << 32) | x3
}

const fn generate_byte_table_row(table_seed: u128, byte_index: usize) -> [u128; 256] {
	let mut row = [0u128; 256];
	let mut i = 0;
	while i < 256 {
		row[i] = generate_byte_table_entry(table_seed, byte_index, i);
		i += 1;
	}
	row
}

const fn generate_byte_table(table_seed: u128) -> [[u128; 256]; 16] {
	let mut table = [[0u128; 256]; 16];
	let mut i = 0;
	while i < 16 {
		table[i] = generate_byte_table_row(table_seed, i);
		i += 1;
	}
	table
}

pub static LINEARIZED_B_TABLE: [[u128; 256]; 16] = generate_byte_table(0x1234567890abcdef);
pub static LINEARIZED_B_INV_TABLE: [[u128; 256]; 16] = generate_byte_table(0xfedcba0987654321);

#[inline]
pub fn linearized_transform_scalar_original<F: Field + WithUnderlier<Underlier = u128>>(
	x: &mut F,
	table: &[[u128; 256]; 16],
) {
	let bases_form: u128 = x.to_underlier();
	let result = (0..16)
		.map(|byte_index| {
			let byte_value = (bases_form >> (byte_index * 8)) & 0xFF;
			table[byte_index][byte_value as usize]
		})
		.fold(0, BitXor::bitxor);

	*x = F::from_underlier(result);
}

pub fn linearized_transform_original(state: &mut [Ghash; 4]) {
	for scalar in state.iter_mut() {
		linearized_transform_scalar(scalar, &LINEARIZED_B_TABLE);
	}
}

#[inline]
pub fn linearized_transform_scalar<F: Field + WithUnderlier<Underlier = u128>>(
	x: &mut F,
	table: &[[u128; 256]; 16],
) {
	let bases_form: u128 = x.to_underlier();

	// Unrolled loop - extract all 16 bytes and look them up directly
	let result = table[0][(bases_form & 0xFF) as usize]
		^ table[1][((bases_form >> 8) & 0xFF) as usize]
		^ table[2][((bases_form >> 16) & 0xFF) as usize]
		^ table[3][((bases_form >> 24) & 0xFF) as usize]
		^ table[4][((bases_form >> 32) & 0xFF) as usize]
		^ table[5][((bases_form >> 40) & 0xFF) as usize]
		^ table[6][((bases_form >> 48) & 0xFF) as usize]
		^ table[7][((bases_form >> 56) & 0xFF) as usize]
		^ table[8][((bases_form >> 64) & 0xFF) as usize]
		^ table[9][((bases_form >> 72) & 0xFF) as usize]
		^ table[10][((bases_form >> 80) & 0xFF) as usize]
		^ table[11][((bases_form >> 88) & 0xFF) as usize]
		^ table[12][((bases_form >> 96) & 0xFF) as usize]
		^ table[13][((bases_form >> 104) & 0xFF) as usize]
		^ table[14][((bases_form >> 112) & 0xFF) as usize]
		^ table[15][((bases_form >> 120) & 0xFF) as usize];

	*x = F::from_underlier(result);
}

pub fn linearized_transform_4(state: &mut [Ghash; 4]) {
	// Unroll the scalar loop as well for maximum performance
	linearized_transform_scalar(&mut state[0], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[1], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[2], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[3], &LINEARIZED_B_TABLE);
}

pub fn linearized_transform_8(state: &mut [Ghash; 8]) {
	// Unroll the scalar loop as well for maximum performance
	linearized_transform_scalar(&mut state[0], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[1], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[2], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[3], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[4], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[5], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[6], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[7], &LINEARIZED_B_TABLE);
}

pub fn linearized_transform_16(state: &mut [Ghash; 16]) {
	// Unroll the scalar loop as well for maximum performance
	linearized_transform_scalar(&mut state[0], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[1], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[2], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[3], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[4], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[5], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[6], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[7], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[8], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[9], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[10], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[11], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[12], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[13], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[14], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[15], &LINEARIZED_B_TABLE);
}

pub fn linearized_transform_32(state: &mut [Ghash; 32]) {
	// Unroll the scalar loop as well for maximum performance
	linearized_transform_scalar(&mut state[0], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[1], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[2], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[3], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[4], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[5], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[6], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[7], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[8], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[9], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[10], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[11], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[12], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[13], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[14], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[15], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[16], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[17], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[18], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[19], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[20], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[21], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[22], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[23], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[24], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[25], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[26], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[27], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[28], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[29], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[30], &LINEARIZED_B_TABLE);
	linearized_transform_scalar(&mut state[31], &LINEARIZED_B_TABLE);
}

// MATRIX MUL

#[inline]
fn mul_by_2(x: Ghash) -> Ghash {
	let val = x.to_underlier();
	let shifted = val << 1;

	// GHASH irreducible polynomial: x^128 + x^7 + x^2 + x + 1
	// When the high bit is set, we need to XOR with the reduction polynomial 0x87
	let result = if val & (1u128 << 127) != 0 {
		shifted ^ 0x87
	} else {
		shifted
	};

	Ghash::from_underlier(result)
}

#[inline]
pub fn matrix_mul(a: &mut [Ghash; 4]) {
	// a = [a0, a1, a2, a3]
	let sum = a[0] + a[1] + a[2] + a[3];
	let a0 = a[0];

	// r0 = 2*a0 + 3*a1 + a2 + a3
	a[0] += sum + mul_by_2(a[0] + a[1]);

	// r1 = a0 + 2*a1 + 3*a2 + a3
	a[1] += sum + mul_by_2(a[1] + a[2]);

	// r2 = a0 + a1 + 2*a2 + 3*a3
	a[2] += sum + mul_by_2(a[2] + a[3]);

	// r3 = 3*a0 + a1 + a2 + 2*a3
	a[3] += sum + mul_by_2(a[3] + a0);
}

#[inline]
pub fn matrix_mul_owned(a: [Ghash; 4]) -> [Ghash; 4] {
	// a = [a0, a1, a2, a3]
	let sum = a[0] + a[1] + a[2] + a[3];

	// r0 = 2*a0 + 3*a1 + a2 + a3
	let r0 = a[0] + sum + mul_by_2(a[0] + a[1]);

	// r1 = a0 + 2*a1 + 3*a2 + a3
	let r1 = a[1] + sum + mul_by_2(a[1] + a[2]);

	// r2 = a0 + a1 + 2*a2 + 3*a3
	let r2 = a[2] + sum + mul_by_2(a[2] + a[3]);

	// r3 = 3*a0 + a1 + a2 + 2*a3
	let r3 = a[3] + sum + mul_by_2(a[3] + a[0]);

	[r0, r1, r2, r3]
}

// ROUND CONSTANTS

pub static K0: [u128; 4] = [
	5192376086697341892868089873170432,
	5192376086697360339612163582722048,
	5192376087906267712482719047876608,
	5192376087906286159226792757428224,
];

pub static K1: [u128; 4] = [
	44917480949925006745161845108910325760,
	44917480949924854621132479769746612715,
	44917480939955094680487035711460671488,
	44917480939955254232645539767773766123,
];

pub fn add_round_constants(state: &mut [Ghash; 4], constants: &[u128; 4]) {
	izip!(state, constants).for_each(|(a, b)| {
		*a += Ghash::from_underlier(*b);
	});
}

pub fn add_round_constants_owned(state: [Ghash; 4], constants: &[u128; 4]) -> [Ghash; 4] {
	[
		state[0] + Ghash::from_underlier(constants[0]),
		state[1] + Ghash::from_underlier(constants[1]),
		state[2] + Ghash::from_underlier(constants[2]),
		state[3] + Ghash::from_underlier(constants[3]),
	]
}

// ROUND FUNCTION

// pub fn round(state: &mut [Ghash; 4]) {
// 	// First half
// 	batch_invert(state);
// 	// linearized_transform(state, &LINEARIZED_B_INV_TABLE);
// 	matrix_mul(state);
// 	add_round_constants(state, &K0);
// 	// Second half
// 	batch_invert(state);
// 	// linearized_transform(state, &LINEARIZED_B_TABLE);
// 	matrix_mul(state);
// 	add_round_constants(state, &K1);
// }

// pub fn round_owned(mut state: [Ghash; 4]) -> [Ghash; 4] {
// 	// First half
// 	state = batch_invert_owned(state);
// 	// linearized_transform(state, &LINEARIZED_B_INV_TABLE);
// 	state = matrix_mul_owned(state);
// 	state = add_round_constants_owned(state, &K0);
// 	// Second half
// 	state = batch_invert_owned(state);
// 	// linearized_transform(state, &LINEARIZED_B_TABLE);
// 	state = matrix_mul_owned(state);
// 	add_round_constants_owned(state, &K1)
// }

pub fn round_4(state: &mut [Ghash; 4]) {
	batch_invert_4(state);
	linearized_transform_4(state);
	batch_invert_4(state);
	linearized_transform_4(state);
}

pub fn round_8(state: &mut [Ghash; 8]) {
	batch_invert_8(state);
	linearized_transform_8(state);
	batch_invert_8(state);
	linearized_transform_8(state);
}

pub fn round_16(state: &mut [Ghash; 16]) {
	batch_invert_16(state);
	linearized_transform_16(state);
	batch_invert_16(state);
	linearized_transform_16(state);
}

pub fn round_32(state: &mut [Ghash; 32]) {
	batch_invert_32(state);
	linearized_transform_32(state);
	batch_invert_32(state);
	linearized_transform_32(state);
}
