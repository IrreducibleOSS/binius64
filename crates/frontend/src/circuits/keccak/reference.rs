pub const PADDING_BYTE: u8 = 0x01;
pub const RATE_BYTES: usize = 136;

// ι round constants
pub const RC: [u64; 24] = [
	0x0000_0000_0000_0001,
	0x0000_0000_0000_8082,
	0x8000_0000_0000_808A,
	0x8000_0000_8000_8000,
	0x0000_0000_0000_808B,
	0x0000_0000_8000_0001,
	0x8000_0000_8000_8081,
	0x8000_0000_0000_8009,
	0x0000_0000_0000_008A,
	0x0000_0000_0000_0088,
	0x0000_0000_8000_8009,
	0x0000_0000_8000_000A,
	0x0000_0000_8000_808B,
	0x8000_0000_0000_008B,
	0x8000_0000_0000_8089,
	0x8000_0000_0000_8003,
	0x8000_0000_0000_8002,
	0x8000_0000_0000_0080,
	0x0000_0000_0000_800A,
	0x8000_0000_8000_000A,
	0x8000_0000_8000_8081,
	0x8000_0000_0000_8080,
	0x0000_0000_8000_0001,
	0x8000_0000_8000_8008,
];

// ρ rotation offsets r[x,y] in lane order (i = x + 5*y)
pub const R: [u32; 25] = [
	0x00, 0x01, 0x3E, 0x1C, 0x1B, 0x24, 0x2C, 0x06, 0x37, 0x14, 0x03, 0x0A, 0x2B, 0x19, 0x27, 0x29,
	0x2D, 0x0F, 0x15, 0x08, 0x12, 0x02, 0x3D, 0x38, 0x0E,
];

#[inline(always)]
pub const fn idx(x: usize, y: usize) -> usize {
	x + 5 * y
}

/// Computes the Keccak-256 hash of a variable length byte message
pub fn keccak_256(data: &[u8]) -> [u8; 32] {
	let mut digest = [0u8; 32];

	const RATE_BYTES: usize = 1088 / 8; // 136
	let mut state = [0u64; 25]; // 1600‑bit sponge state

	// absorb
	let mut offset = 0;
	while offset + RATE_BYTES <= data.len() {
		xor_bytes_into_state(&mut state, &data[offset..offset + RATE_BYTES]);
		keccak_f1600_reference(&mut state);
		offset += RATE_BYTES;
	}

	// absorb final padded block
	let mut block = [0u8; RATE_BYTES];
	let tail = &data[offset..];
	block[..tail.len()].copy_from_slice(tail);
	block[tail.len()] = PADDING_BYTE;
	block[RATE_BYTES - 1] |= 0x80;
	xor_bytes_into_state(&mut state, &block);
	keccak_f1600_reference(&mut state);

	// squeeze
	for i in 0..32 {
		let lane = state[i / 8];
		digest[i] = (lane >> (8 * (i % 8))) as u8;
	}

	digest
}

fn xor_bytes_into_state(state: &mut [u64; 25], block: &[u8]) {
	for i in 0..RATE_BYTES {
		state[i / 8] ^= u64::from(block[i]) << (8 * (i % 8));
	}
}

#[allow(unused_variables)]
pub fn theta_reference(state: &mut [u64; 25], round: usize) {
	let mut c = [0u64; 5];
	for x in 0..5 {
		c[x] = state[idx(x, 0)]
			^ state[idx(x, 1)]
			^ state[idx(x, 2)]
			^ state[idx(x, 3)]
			^ state[idx(x, 4)];
	}
	let d = [
		c[4] ^ c[1].rotate_left(1),
		c[0] ^ c[2].rotate_left(1),
		c[1] ^ c[3].rotate_left(1),
		c[2] ^ c[4].rotate_left(1),
		c[3] ^ c[0].rotate_left(1),
	];

	for y in 0..5 {
		for x in 0..5 {
			state[idx(x, y)] ^= d[x];
		}
	}
}

#[inline(always)]
#[allow(unused_variables)]
pub fn rho_pi_reference(state: &mut [u64; 25], round: usize) {
	let mut temp = [state[0]; 25];
	for y in 0..5 {
		for x in 0..5 {
			temp[idx(y, (2 * x + 3 * y) % 5)] = state[idx(x, y)].rotate_left(R[idx(x, y)]);
		}
	}
	*state = temp;
}

pub fn iota_reference(state: &mut [u64; 25], round: usize) {
	state[0] ^= RC[round];
}

#[inline(always)]
pub fn chi_reference(state: &mut [u64; 25]) {
	for y in 0..5 {
		let a0 = state[idx(0, y)];
		let a1 = state[idx(1, y)];
		let a2 = state[idx(2, y)];
		let a3 = state[idx(3, y)];
		let a4 = state[idx(4, y)];
		state[idx(0, y)] = a0 ^ ((!a1) & a2);
		state[idx(1, y)] = a1 ^ ((!a2) & a3);
		state[idx(2, y)] = a2 ^ ((!a3) & a4);
		state[idx(3, y)] = a3 ^ ((!a4) & a0);
		state[idx(4, y)] = a4 ^ ((!a0) & a1);
	}
}

pub fn keccak_permutation_round_reference(state: &mut [u64; 25], round: usize) {
	theta_reference(state, round);
	rho_pi_reference(state, round);
	chi_reference(state);
	iota_reference(state, round);
}

pub fn keccak_f1600_reference(state: &mut [u64; 25]) {
	for round in 0..24 {
		keccak_permutation_round_reference(state, round);
	}
}

#[cfg(test)]
mod tests {
	use rand::{Rng, SeedableRng, rngs::StdRng};
	use sha3::{Digest, Keccak256};
	use std::iter::repeat_n;

	use super::*;

	#[test]
	fn test_keccak_crate_vs_reference() {
		let mut rng = StdRng::seed_from_u64(0);

		let message = repeat_n(rng.random_range(0..=255), 100).collect::<Vec<_>>();

		let mut hasher = Keccak256::new();
		hasher.update(message.clone());
		let crate_digest: [u8; 32] = hasher.finalize().into();

		let digest = keccak_256(&message);

		assert_eq!(crate_digest, digest);
	}
}
