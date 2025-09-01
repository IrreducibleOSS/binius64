//! Reference implementations for operations
//! 
//! Pure Rust implementations used to verify expression evaluation correctness.

/// Bitwise operations
pub fn xor(a: u64, b: u64) -> u64 { a ^ b }
pub fn and(a: u64, b: u64) -> u64 { a & b }
pub fn or(a: u64, b: u64) -> u64 { a | b }
pub fn not(a: u64) -> u64 { !a }

/// Shift operations
pub fn shl(a: u64, amount: u8) -> u64 { a << amount }
pub fn shr(a: u64, amount: u8) -> u64 { a >> amount }
pub fn sar(a: u64, amount: u8) -> u64 { ((a as i64) >> amount) as u64 }
pub fn rol(a: u64, amount: u8) -> u64 { a.rotate_left(amount as u32) }
pub fn ror(a: u64, amount: u8) -> u64 { a.rotate_right(amount as u32) }

/// 32-bit arithmetic
pub fn add32(a: u32, b: u32) -> u32 { a.wrapping_add(b) }
pub fn sub32(a: u32, b: u32) -> u32 { a.wrapping_sub(b) }
pub fn mul32(a: u32, b: u32) -> u64 { (a as u64) * (b as u64) }

/// 64-bit arithmetic  
pub fn add64(a: u64, b: u64) -> u64 { a.wrapping_add(b) }
pub fn sub64(a: u64, b: u64) -> u64 { a.wrapping_sub(b) }
pub fn mul64(a: u64, b: u64) -> u64 { a.wrapping_mul(b) }

/// Composite operations
pub fn xor3(a: u64, b: u64, c: u64) -> u64 { a ^ b ^ c }
pub fn xor4(a: u64, b: u64, c: u64, d: u64) -> u64 { a ^ b ^ c ^ d }
pub fn mux(cond: u64, true_val: u64, false_val: u64) -> u64 {
    if cond != 0 { true_val } else { false_val }
}
pub fn keccak_chi(a: u64, b: u64, c: u64) -> u64 { a ^ ((!b) & c) }