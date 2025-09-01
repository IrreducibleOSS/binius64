//! SHA256 implementation

use crate::expr::Expr;
use crate::types::U32;
use crate::ops::{add, xor, and, not, ror32, shr32};
use crate::constant;

/// SHA256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
pub const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// SHA256 operations

/// Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)
fn ch(x: &Expr<U32>, y: &Expr<U32>, z: &Expr<U32>) -> Expr<U32> {
    xor(&and(x, y), &and(&not(x), z))
}

/// Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
fn maj(x: &Expr<U32>, y: &Expr<U32>, z: &Expr<U32>) -> Expr<U32> {
    xor(&xor(&and(x, y), &and(x, z)), &and(y, z))
}

/// Σ0(x) = ROTR(x, 2) XOR ROTR(x, 13) XOR ROTR(x, 22)
fn big_sigma_0(x: &Expr<U32>) -> Expr<U32> {
    xor(&xor(&ror32(x, 2), &ror32(x, 13)), &ror32(x, 22))
}

/// Σ1(x) = ROTR(x, 6) XOR ROTR(x, 11) XOR ROTR(x, 25)
fn big_sigma_1(x: &Expr<U32>) -> Expr<U32> {
    xor(&xor(&ror32(x, 6), &ror32(x, 11)), &ror32(x, 25))
}

/// σ0(x) = ROTR(x, 7) XOR ROTR(x, 18) XOR SHR(x, 3)
fn small_sigma_0(x: &Expr<U32>) -> Expr<U32> {
    xor(&xor(&ror32(x, 7), &ror32(x, 18)), &shr32(x, 3))
}

/// σ1(x) = ROTR(x, 17) XOR ROTR(x, 19) XOR SHR(x, 10)
fn small_sigma_1(x: &Expr<U32>) -> Expr<U32> {
    xor(&xor(&ror32(x, 17), &ror32(x, 19)), &shr32(x, 10))
}

/// SHA256 compression function
/// 
/// Takes the current hash state and a 512-bit message block,
/// performs the compression rounds, and returns the new state.
pub fn compress(
    state: &[Expr<U32>; 8], 
    block: &[Expr<U32>; 16],
    num_rounds: usize
) -> [Expr<U32>; 8] {
    // Expand message schedule
    let w = expand_message_schedule(block, num_rounds);
    
    // Initialize working variables
    let mut a = state[0].clone();
    let mut b = state[1].clone();
    let mut c = state[2].clone();
    let mut d = state[3].clone();
    let mut e = state[4].clone();
    let mut f = state[5].clone();
    let mut g = state[6].clone();
    let mut h = state[7].clone();
    
    // Main compression loop
    for i in 0..num_rounds {
        // T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
        let s1 = big_sigma_1(&e);
        let ch_efg = ch(&e, &f, &g);
        let k_const = constant::<U32>(K[i] as u64);
        
        // Chain additions: ((h + Σ1) + Ch) + K[i]) + W[i]
        let t1_partial1 = add(&h, &s1);
        let t1_partial2 = add(&t1_partial1, &ch_efg);
        let t1_partial3 = add(&t1_partial2, &k_const);
        let t1 = add(&t1_partial3, &w[i]);
        
        // T2 = Σ0(a) + Maj(a,b,c)
        let s0 = big_sigma_0(&a);
        let maj_abc = maj(&a, &b, &c);
        let t2 = add(&s0, &maj_abc);
        
        // Update working variables
        h = g;
        g = f;
        f = e;
        e = add(&d, &t1);
        d = c;
        c = b;
        b = a;
        a = add(&t1, &t2);
    }
    
    // Add compressed chunk to current hash value
    [
        add(&state[0], &a),
        add(&state[1], &b),
        add(&state[2], &c),
        add(&state[3], &d),
        add(&state[4], &e),
        add(&state[5], &f),
        add(&state[6], &g),
        add(&state[7], &h),
    ]
}

/// Expand message schedule for SHA256
/// 
/// Takes the 16 32-bit words of the message block and expands them
/// to the number of words needed for the specified rounds.
fn expand_message_schedule(block: &[Expr<U32>], num_rounds: usize) -> Vec<Expr<U32>> {
    assert!(block.len() >= 16, "Block must have at least 16 words");
    
    let mut w = Vec::with_capacity(num_rounds);
    
    // First 16 words are the message block itself
    for i in 0..16.min(num_rounds) {
        w.push(block[i].clone());
    }
    
    // Expansion: W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
    for i in 16..num_rounds {
        let s0 = small_sigma_0(&w[i - 15]);
        let s1 = small_sigma_1(&w[i - 2]);
        
        // Chain the additions: ((W[t-16] + σ0) + W[t-7]) + σ1
        let temp1 = add(&w[i - 16], &s0);
        let temp2 = add(&temp1, &w[i - 7]);
        let word = add(&temp2, &s1);
        
        w.push(word);
    }
    
    w
}