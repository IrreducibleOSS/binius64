//! Keccak-f[1600] permutation implementation using Beamish delayed binding

use crate::*;
use crate::types::U64;

/// Number of 64-bit words in Keccak state
pub const STATE_SIZE: usize = 25;

/// Number of rounds in full Keccak-f[1600]
pub const ROUNDS: usize = 24;

/// Round constants for iota step
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

/// Rotation offsets for rho step
pub const R: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41,
    45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Convert (x,y) coordinates to linear index
#[inline(always)]
pub const fn idx(x: usize, y: usize) -> usize {
    x + 5 * y
}

/// Rotate left for 64-bit values
fn rotl64(x: &Expr<U64>, n: u32) -> Expr<U64> {
    if n == 0 {
        x.clone()
    } else if n == 32 {
        // Special case for 32-bit rotation
        let lo = shr(x, 32);
        let hi = shl(x, 32);
        xor(&lo, &hi)
    } else if n < 32 {
        let left = shl(x, n as u8);
        let right = shr(x, (64 - n) as u8);
        xor(&left, &right)
    } else {
        let left = shl(x, n as u8);
        let right = shr(x, (64 - n) as u8);
        xor(&left, &right)
    }
}

/// Theta step: column parity
fn theta(state: &mut [Expr<U64>; STATE_SIZE]) {
    // Compute column parities
    let mut c = [(); 5].map(|_| constant::<U64>(0));
    for x in 0..5 {
        c[x] = xor(&state[idx(x, 0)], &state[idx(x, 1)]);
        c[x] = xor(&c[x], &state[idx(x, 2)]);
        c[x] = xor(&c[x], &state[idx(x, 3)]);
        c[x] = xor(&c[x], &state[idx(x, 4)]);
    }
    
    // Compute D values
    let mut d = [(); 5].map(|_| constant::<U64>(0));
    for x in 0..5 {
        let x_minus_1 = (x + 4) % 5;
        let x_plus_1 = (x + 1) % 5;
        d[x] = xor(&c[x_minus_1], &rotl64(&c[x_plus_1], 1));
    }
    
    // XOR D values into state
    for x in 0..5 {
        for y in 0..5 {
            state[idx(x, y)] = xor(&state[idx(x, y)], &d[x]);
        }
    }
}

/// Rho and Pi steps: rotations and permutation
fn rho_pi(state: &mut [Expr<U64>; STATE_SIZE]) {
    let mut temp = [(); STATE_SIZE].map(|_| constant::<U64>(0));
    
    // First element doesn't rotate
    temp[idx(0, 0)] = state[idx(0, 0)].clone();
    
    // Apply rho (rotation) and pi (permutation) together
    for x in 0..5 {
        for y in 0..5 {
            if x == 0 && y == 0 {
                continue; // Already handled
            }
            let src_idx = idx(x, y);
            let dst_x = y;
            let dst_y = (2 * x + 3 * y) % 5;
            let dst_idx = idx(dst_x, dst_y);
            
            temp[dst_idx] = rotl64(&state[src_idx], R[src_idx]);
        }
    }
    
    *state = temp;
}

/// Chi step: non-linear transformation
fn chi(state: &mut [Expr<U64>; STATE_SIZE]) {
    for y in 0..5 {
        // Save row values
        let row = [
            state[idx(0, y)].clone(),
            state[idx(1, y)].clone(),
            state[idx(2, y)].clone(),
            state[idx(3, y)].clone(),
            state[idx(4, y)].clone(),
        ];
        
        // Apply chi: a XOR ((NOT b) AND c)
        for x in 0..5 {
            let b = &row[(x + 1) % 5];
            let c = &row[(x + 2) % 5];
            state[idx(x, y)] = xor(&row[x], &and(&not(b), c));
        }
    }
}

/// Iota step: add round constant
fn iota(state: &mut [Expr<U64>; STATE_SIZE], round: usize) {
    state[0] = xor(&state[0], &constant::<U64>(RC[round]));
}

/// Single round of Keccak-f[1600]
fn keccak_round(state: &mut [Expr<U64>; STATE_SIZE], round: usize) {
    theta(state);
    rho_pi(state);
    chi(state);
    iota(state, round);
}

/// Full Keccak-f[1600] permutation
pub fn keccak_f(state: &[Expr<U64>; STATE_SIZE], num_rounds: usize) -> [Expr<U64>; STATE_SIZE] {
    let mut result = state.clone();
    
    for round in 0..num_rounds {
        keccak_round(&mut result, round);
    }
    
    result
}