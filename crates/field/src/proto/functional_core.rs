// Approach 4: Functional Core - Pure Functions with Method Shells
//
// Idea: Separate ALL operations from types. Types are just thin wrappers around raw data.
// All operations are pure const functions in modules. This makes the distinction between
// field operations and bitwise operations clear at the call site.
//
// Advantages:
// - Pure functional core is easy to test and reason about
// - Const functions can be used in const contexts
// - No abstraction leak - operations are exactly what they say
// - Easy to add new operations without changing types
//
// Operations are explicit functions with clear names, not methods that could mislead.
// The functional approach makes the distinction between operation types obvious.

// Everything wrapped in its own module to avoid conflicts
pub mod impl_functional_core {
    use std::ops::{Add, BitAnd, Mul};

    // Pure data types - no methods
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct B1(pub u8);  // 1-bit field GF(2)
    
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct B64(pub u64);

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct B128(pub u128);

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct Ghash(pub u128);

    // All operations as pure const functions
    pub mod ops {
        // 1-bit operations (GF(2))
        pub mod b1 {
            pub const fn zero() -> u8 { 0 }
            pub const fn one() -> u8 { 1 }
            
            // Field operations
            pub const fn field_add(a: u8, b: u8) -> u8 {
                (a ^ b) & 1
            }
            
            pub const fn field_mul(a: u8, b: u8) -> u8 {
                a & b & 1
            }
            
            pub fn field_square(a: u8) -> u8 {
                a & 1  // In GF(2), x^2 = x
            }
            
            pub fn field_inverse(a: u8) -> Option<u8> {
                if a == 0 {
                    None
                } else {
                    Some(1)  // 1 is its own inverse
                }
            }
            
            // Bitwise operations
            pub const fn bit_and(a: u8, b: u8) -> u8 {
                a & b & 1
            }
            
            pub const fn bit_xor(a: u8, b: u8) -> u8 {
                (a ^ b) & 1
            }
            
            pub fn mask_from_byte(byte: u8) -> u8 {
                byte & 1  // Just take LSB
            }
        }
        
        // 64-bit operations
        pub mod b64 {
            pub const fn zero() -> u64 { 0 }
            pub const fn one() -> u64 { 1 }
            
            // Field operations
            pub const fn field_add(a: u64, b: u64) -> u64 {
                a ^ b
            }
            
            pub fn field_mul(a: u64, b: u64) -> u64 {
                let mut result = 0u64;
                let mut x = a;
                let mut y = b;
                
                while y != 0 {
                    if y & 1 != 0 {
                        result ^= x;
                    }
                    x <<= 1;
                    y >>= 1;
                    // Would add polynomial reduction here
                }
                result
            }
            
            pub fn field_square(a: u64) -> u64 {
                field_mul(a, a)
            }
            
            pub fn field_inverse(a: u64) -> Option<u64> {
                if a == 0 {
                    None
                } else {
                    Some(1)  // Placeholder
                }
            }
            
            // Bitwise operations - clearly separate
            pub const fn bit_and(a: u64, b: u64) -> u64 {
                a & b
            }
            
            pub const fn bit_xor(a: u64, b: u64) -> u64 {
                a ^ b
            }
            
            pub const fn bit_or(a: u64, b: u64) -> u64 {
                a | b
            }
            
            pub fn mask_from_byte(byte: u8) -> u64 {
                let mut mask = 0u64;
                for i in 0..8 {
                    if (byte >> i) & 1 != 0 {
                        mask |= 0xFF << (i * 8);
                    }
                }
                mask
            }
        }
        
        // 128-bit operations
        pub mod b128 {
            pub const fn zero() -> u128 { 0 }
            pub const fn one() -> u128 { 1 }
            
            pub const fn field_add(a: u128, b: u128) -> u128 {
                a ^ b
            }
            
            pub fn field_mul(a: u128, b: u128) -> u128 {
                let mut result = 0u128;
                let mut x = a;
                let mut y = b;
                
                while y != 0 {
                    if y & 1 != 0 {
                        result ^= x;
                    }
                    x <<= 1;
                    y >>= 1;
                }
                result
            }
            
            pub fn field_square(a: u128) -> u128 {
                field_mul(a, a)
            }
            
            pub const fn bit_and(a: u128, b: u128) -> u128 {
                a & b
            }
            
            pub const fn bit_xor(a: u128, b: u128) -> u128 {
                a ^ b
            }
            
            pub fn mask_from_byte(byte: u8) -> u128 {
                let mut mask = 0u128;
                for i in 0..8 {
                    if (byte >> i) & 1 != 0 {
                        mask |= (0xFF as u128) << (i * 8);
                    }
                }
                mask
            }
        }
        
        // GHASH-specific operations
        pub mod ghash {
            pub const fn zero() -> u128 { 0 }
            pub const fn one() -> u128 { 1 }
            
            pub const fn field_add(a: u128, b: u128) -> u128 {
                a ^ b
            }
            
            pub fn field_mul(a: u128, b: u128) -> u128 {
                let mut result = 0u128;
                let mut x = a;
                let mut y = b;
                
                for _ in 0..128 {
                    if y & 1 != 0 {
                        result ^= x;
                    }
                    let carry = x >> 127;
                    x <<= 1;
                    if carry != 0 {
                        x ^= 0x87;  // GHASH reduction polynomial
                    }
                    y >>= 1;
                }
                result
            }
            
            pub fn field_square(a: u128) -> u128 {
                field_mul(a, a)
            }
            
            pub const fn bit_and(a: u128, b: u128) -> u128 {
                a & b
            }
            
            pub const fn bit_xor(a: u128, b: u128) -> u128 {
                a ^ b
            }
            
            pub fn mask_from_byte(byte: u8) -> u128 {
                let mut mask = 0u128;
                for i in 0..8 {
                    if (byte >> i) & 1 != 0 {
                        mask |= (0xFF as u128) << (i * 8);
                    }
                }
                mask
            }
        }
    }

    // Convenience trait implementations just delegate to functions
    impl Add for B1 {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            B1(ops::b1::field_add(self.0, other.0))
        }
    }

    impl Mul for B1 {
        type Output = Self;
        fn mul(self, other: Self) -> Self {
            B1(ops::b1::field_mul(self.0, other.0))
        }
    }

    impl BitAnd for B1 {
        type Output = Self;
        fn bitand(self, other: Self) -> Self {
            B1(ops::b1::bit_and(self.0, other.0))
        }
    }

    impl Add for B64 {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            B64(ops::b64::field_add(self.0, other.0))
        }
    }

    impl Mul for B64 {
        type Output = Self;
        fn mul(self, other: Self) -> Self {
            B64(ops::b64::field_mul(self.0, other.0))
        }
    }

    impl BitAnd for B64 {
        type Output = Self;
        fn bitand(self, other: Self) -> Self {
            B64(ops::b64::bit_and(self.0, other.0))
        }
    }

    impl Add for B128 {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            B128(ops::b128::field_add(self.0, other.0))
        }
    }

    impl Mul for B128 {
        type Output = Self;
        fn mul(self, other: Self) -> Self {
            B128(ops::b128::field_mul(self.0, other.0))
        }
    }

    impl BitAnd for B128 {
        type Output = Self;
        fn bitand(self, other: Self) -> Self {
            B128(ops::b128::bit_and(self.0, other.0))
        }
    }

    impl Add for Ghash {
        type Output = Self;
        fn add(self, other: Self) -> Self {
            Ghash(ops::ghash::field_add(self.0, other.0))
        }
    }

    impl Mul for Ghash {
        type Output = Self;
        fn mul(self, other: Self) -> Self {
            Ghash(ops::ghash::field_mul(self.0, other.0))
        }
    }

    impl BitAnd for Ghash {
        type Output = Self;
        fn bitand(self, other: Self) -> Self {
            Ghash(ops::ghash::bit_and(self.0, other.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::impl_functional_core::*;
    use super::impl_functional_core::ops::{b1, b64, b128, ghash};
    
    #[test]
    fn test_field_arithmetic() {
        // Test B1 (GF(2))
        let a1 = 1u8;
        let b1 = 1u8;
        
        // 1 + 1 = 0 in GF(2)
        let sum1 = b1::field_add(a1, b1);
        assert_eq!(sum1, 0);
        
        // 1 * 1 = 1 in GF(2)
        let prod1 = b1::field_mul(a1, b1);
        assert_eq!(prod1, 1);
        
        // Using wrapper types
        let a1_wrapped = B1(1);
        let b1_wrapped = B1(1);
        let sum1_wrapped = a1_wrapped + b1_wrapped;
        assert_eq!(sum1_wrapped.0, 0);
        
        // Test B64 - using functions directly
        let a = 0x1234u64;
        let b = 0x5678u64;
        
        let sum = b64::field_add(a, b);
        assert_eq!(sum, 0x1234 ^ 0x5678);
        
        // Or using wrapper types
        let a_wrapped = B64(a);
        let b_wrapped = B64(b);
        let sum_wrapped = a_wrapped + b_wrapped;
        assert_eq!(sum_wrapped.0, sum);
        
        // Test B128
        let c = 0x1234u128;
        let d = 0x5678u128;
        let sum128 = b128::field_add(c, d);
        assert_eq!(sum128, 0x1234 ^ 0x5678);
        
        // Test Ghash
        let e = 0x1234u128;
        let f = 0x5678u128;
        let sum_ghash = ghash::field_add(e, f);
        assert_eq!(sum_ghash, 0x1234 ^ 0x5678);
    }
    
    #[test]
    fn test_field_properties() {
        // Test identity: a + 0 = a
        let a = 0x12u64;
        assert_eq!(b64::field_add(a, b64::zero()), a);
        
        // Test square
        let sq = b64::field_square(a);
        assert_eq!(sq, b64::field_mul(a, a));
        
        // Same for B128
        let b = 0x12u128;
        assert_eq!(b128::field_add(b, b128::zero()), b);
        
        // Same for Ghash
        let c = 0x12u128;
        assert_eq!(ghash::field_add(c, ghash::zero()), c);
    }
    
    #[test]
    fn test_shift_optimization() {
        // The controversial optimization - now clear
        
        let mut acc = 0u64;
        let val = 0x1234567890ABCDEFu64;
        let byte: u8 = 0b10101010;
        
        // Create mask - clearly a bit operation
        let mask = b64::mask_from_byte(byte);
        
        // Apply mask - explicitly using bit_and function
        let masked = b64::bit_and(val, mask);
        
        // Add to accumulator - field operation
        acc = b64::field_add(acc, masked);
        
        // Clear what's happening:
        // - mask_from_byte creates a bit pattern
        // - bit_and applies it (NOT field multiplication)
        // - field_add accumulates the result
        
        // Or using wrapper types
        let mut acc_wrapped = B64(0);
        let val_wrapped = B64(val);
        let mask_wrapped = B64(mask);
        let masked_wrapped = val_wrapped & mask_wrapped;  // BitAnd trait
        acc_wrapped = acc_wrapped + masked_wrapped;  // Add trait
        
        // Test B128
        let mut acc128 = 0u128;
        let val128 = 0x1234567890ABCDEF1234567890ABCDEFu128;
        let mask128 = b128::mask_from_byte(byte);
        let masked128 = b128::bit_and(val128, mask128);
        acc128 = b128::field_add(acc128, masked128);
        
        // Test Ghash
        let mut acc_ghash = 0u128;
        let val_ghash = 0x1234567890ABCDEF1234567890ABCDEFu128;
        let mask_ghash = ghash::mask_from_byte(byte);
        let masked_ghash = ghash::bit_and(val_ghash, mask_ghash);
        acc_ghash = ghash::field_add(acc_ghash, masked_ghash);
        
        // Just to use the variables
        let _ = (acc, acc_wrapped, acc128, acc_ghash);
    }
    
    #[test]
    fn test_mixed_operations() {
        // Mixing field and bit operations with clarity
        
        let a = 0xAAAAu64;
        let b = 0xBBBBu64;
        let mask = 0xFF00u64;
        
        // Field multiplication - explicit function call
        let product = b64::field_mul(a, b);
        
        // Bitwise masking - different function, clear intent
        let masked = b64::bit_and(product, mask);
        
        // Field addition
        let _result = b64::field_add(masked, 0x1111);
        
        // No confusion possible - functions are explicit
        
        // Same with wrapper types
        let a_wrapped = B64(a);
        let b_wrapped = B64(b);
        let mask_wrapped = B64(mask);
        let product_wrapped = a_wrapped * b_wrapped;
        let masked_wrapped = product_wrapped & mask_wrapped;
        let _result_wrapped = masked_wrapped + B64(0x1111);
        
        // Test B128
        let a128 = 0xAAAAu128;
        let b128 = 0xBBBBu128;
        let mask128 = 0xFF00u128;
        let product128 = b128::field_mul(a128, b128);
        let masked128 = b128::bit_and(product128, mask128);
        let _result128 = b128::field_add(masked128, 0x1111);
        
        // Test Ghash
        let a_ghash = 0xAAAAu128;
        let b_ghash = 0xBBBBu128;
        let mask_ghash = 0xFF00u128;
        let product_ghash = ghash::field_mul(a_ghash, b_ghash);
        let masked_ghash = ghash::bit_and(product_ghash, mask_ghash);
        let _result_ghash = ghash::field_add(masked_ghash, 0x1111);
    }
}