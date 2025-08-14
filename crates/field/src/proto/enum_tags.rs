// Approach 5: Enum Tags - Single Type for Everything
//
// Idea: Most radical simplification - eliminate the type zoo entirely. Use a single enum
// that can represent any field. Runtime dispatch instead of compile-time types. This is the
// opposite of the current heavily generic approach.
//
// Advantages:
// - Simpler type system - just one type
// - Easy to add new fields without changing APIs
// - Clear operations - methods explicitly handle each variant
// - No generic type parameter explosion
//
// Disadvantages:
// - Runtime overhead from enum matching
// - Can mix incompatible fields at runtime (but we detect and panic)
//
// Operations are explicit methods with clear names that show their purpose.
// Field operations and bitwise operations are completely distinct.

// Everything wrapped in its own module to avoid conflicts
pub mod impl_enum_tags {
    use std::ops::{Add, BitAnd, Mul};

    // Single enum for all binary fields
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum BinaryField {
        B1(u8),  // 1-bit field GF(2)
        B64(u64),
        B128(u128),
        Ghash(u128),
    }

    impl BinaryField {
        // Constructors
        pub fn b1(value: u8) -> Self {
            BinaryField::B1(value & 1)  // Ensure it's 0 or 1
        }
        
        pub fn b64(value: u64) -> Self {
            BinaryField::B64(value)
        }
        
        pub fn b128(value: u128) -> Self {
            BinaryField::B128(value)
        }
        
        pub fn ghash(value: u128) -> Self {
            BinaryField::Ghash(value)
        }
        
        // Constants
        pub fn zero_b1() -> Self {
            BinaryField::B1(0)
        }
        
        pub fn zero_b64() -> Self {
            BinaryField::B64(0)
        }
        
        pub fn zero_b128() -> Self {
            BinaryField::B128(0)
        }
        
        pub fn zero_ghash() -> Self {
            BinaryField::Ghash(0)
        }
        
        pub fn one_b1() -> Self {
            BinaryField::B1(1)
        }
        
        pub fn one_b64() -> Self {
            BinaryField::B64(1)
        }
        
        pub fn one_b128() -> Self {
            BinaryField::B128(1)
        }
        
        pub fn one_ghash() -> Self {
            BinaryField::Ghash(1)
        }
        
        // Field operations
        pub fn field_add(&self, other: &Self) -> Self {
            match (self, other) {
                (BinaryField::B1(a), BinaryField::B1(b)) => BinaryField::B1((a ^ b) & 1),
                (BinaryField::B64(a), BinaryField::B64(b)) => BinaryField::B64(a ^ b),
                (BinaryField::B128(a), BinaryField::B128(b)) => BinaryField::B128(a ^ b),
                (BinaryField::Ghash(a), BinaryField::Ghash(b)) => BinaryField::Ghash(a ^ b),
                _ => panic!("Type mismatch in field_add"),
            }
        }
        
        pub fn field_mul(&self, other: &Self) -> Self {
            match (self, other) {
                (BinaryField::B1(a), BinaryField::B1(b)) => {
                    // In GF(2), multiplication is AND
                    BinaryField::B1(a & b)
                }
                (BinaryField::B64(a), BinaryField::B64(b)) => {
                    // Simplified carryless multiplication
                    let mut result = 0u64;
                    let mut x = *a;
                    let mut y = *b;
                    
                    while y != 0 {
                        if y & 1 != 0 {
                            result ^= x;
                        }
                        x <<= 1;
                        y >>= 1;
                    }
                    BinaryField::B64(result)
                }
                (BinaryField::B128(a), BinaryField::B128(b)) => {
                    let mut result = 0u128;
                    let mut x = *a;
                    let mut y = *b;
                    
                    while y != 0 {
                        if y & 1 != 0 {
                            result ^= x;
                        }
                        x <<= 1;
                        y >>= 1;
                    }
                    BinaryField::B128(result)
                }
                (BinaryField::Ghash(a), BinaryField::Ghash(b)) => {
                    let mut result = 0u128;
                    let mut x = *a;
                    let mut y = *b;
                    
                    for _ in 0..128 {
                        if y & 1 != 0 {
                            result ^= x;
                        }
                        let carry = x >> 127;
                        x <<= 1;
                        if carry != 0 {
                            x ^= 0x87;  // GHASH reduction
                        }
                        y >>= 1;
                    }
                    BinaryField::Ghash(result)
                }
                _ => panic!("Type mismatch in field_mul"),
            }
        }
        
        pub fn field_square(&self) -> Self {
            self.field_mul(self)
        }
        
        // Bitwise operations - explicitly NOT field operations
        pub fn bit_and(&self, mask: &Self) -> Self {
            match (self, mask) {
                (BinaryField::B1(a), BinaryField::B1(m)) => BinaryField::B1(a & m),
                (BinaryField::B64(a), BinaryField::B64(m)) => BinaryField::B64(a & m),
                (BinaryField::B128(a), BinaryField::B128(m)) => BinaryField::B128(a & m),
                (BinaryField::Ghash(a), BinaryField::Ghash(m)) => BinaryField::Ghash(a & m),
                _ => panic!("Type mismatch in bit_and"),
            }
        }
        
        pub fn bit_xor(&self, other: &Self) -> Self {
            match (self, other) {
                (BinaryField::B1(a), BinaryField::B1(b)) => BinaryField::B1((a ^ b) & 1),
                (BinaryField::B64(a), BinaryField::B64(b)) => BinaryField::B64(a ^ b),
                (BinaryField::B128(a), BinaryField::B128(b)) => BinaryField::B128(a ^ b),
                (BinaryField::Ghash(a), BinaryField::Ghash(b)) => BinaryField::Ghash(a ^ b),
                _ => panic!("Type mismatch in bit_xor"),
            }
        }
        
        // Mask creation
        pub fn mask_from_byte_b1(byte: u8) -> Self {
            // For 1-bit field, just take the LSB
            BinaryField::B1(byte & 1)
        }
        
        pub fn mask_from_byte_b64(byte: u8) -> Self {
            let mut mask = 0u64;
            for i in 0..8 {
                if (byte >> i) & 1 != 0 {
                    mask |= 0xFF << (i * 8);
                }
            }
            BinaryField::B64(mask)
        }
        
        pub fn mask_from_byte_b128(byte: u8) -> Self {
            let mut mask = 0u128;
            for i in 0..8 {
                if (byte >> i) & 1 != 0 {
                    mask |= (0xFF as u128) << (i * 8);
                }
            }
            BinaryField::B128(mask)
        }
        
        pub fn mask_from_byte_ghash(byte: u8) -> Self {
            let mut mask = 0u128;
            for i in 0..8 {
                if (byte >> i) & 1 != 0 {
                    mask |= (0xFF as u128) << (i * 8);
                }
            }
            BinaryField::Ghash(mask)
        }
    }

    // Convenience trait implementations
    impl Add for BinaryField {
        type Output = Self;
        
        fn add(self, other: Self) -> Self {
            self.field_add(&other)
        }
    }

    impl Mul for BinaryField {
        type Output = Self;
        
        fn mul(self, other: Self) -> Self {
            self.field_mul(&other)
        }
    }

    impl BitAnd for BinaryField {
        type Output = Self;
        
        fn bitand(self, other: Self) -> Self {
            self.bit_and(&other)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::impl_enum_tags::*;
    
    #[test]
    fn test_field_arithmetic() {
        // Test B1 (GF(2))
        let a1 = BinaryField::b1(1);
        let b1 = BinaryField::b1(1);
        
        // 1 + 1 = 0 in GF(2)
        let sum1 = a1.field_add(&b1);
        match sum1 {
            BinaryField::B1(val) => assert_eq!(val, 0),
            _ => panic!("Wrong type"),
        }
        
        // 1 * 1 = 1 in GF(2)
        let prod1 = a1.field_mul(&b1);
        match prod1 {
            BinaryField::B1(val) => assert_eq!(val, 1),
            _ => panic!("Wrong type"),
        }
        
        // Test B64
        let a = BinaryField::b64(0x1234);
        let b = BinaryField::b64(0x5678);
        
        let sum = a.field_add(&b);
        match sum {
            BinaryField::B64(val) => assert_eq!(val, 0x1234 ^ 0x5678),
            _ => panic!("Wrong type"),
        }
        
        // Also works with + operator
        let sum2 = a + b;
        assert_eq!(sum, sum2);
        
        // Test B128
        let c = BinaryField::b128(0x1234);
        let d = BinaryField::b128(0x5678);
        let sum128 = c.field_add(&d);
        match sum128 {
            BinaryField::B128(val) => assert_eq!(val, 0x1234 ^ 0x5678),
            _ => panic!("Wrong type"),
        }
        
        // Test Ghash
        let e = BinaryField::ghash(0x1234);
        let f = BinaryField::ghash(0x5678);
        let sum_ghash = e.field_add(&f);
        match sum_ghash {
            BinaryField::Ghash(val) => assert_eq!(val, 0x1234 ^ 0x5678),
            _ => panic!("Wrong type"),
        }
    }
    
    #[test]
    fn test_field_properties() {
        // Test B1 properties
        let a1 = BinaryField::b1(1);
        let zero1 = BinaryField::zero_b1();
        let one1 = BinaryField::one_b1();
        
        // Identity: a + 0 = a
        assert_eq!(a1.field_add(&zero1), a1);
        
        // Identity: a * 1 = a
        assert_eq!(a1.field_mul(&one1), a1);
        
        // Test identity: a + 0 = a
        let a = BinaryField::b64(0x12);
        let zero = BinaryField::zero_b64();
        assert_eq!(a.field_add(&zero), a);
        
        // Test square
        let sq = a.field_square();
        assert_eq!(sq, a.field_mul(&a));
        
        // Same for B128
        let b = BinaryField::b128(0x12);
        let zero128 = BinaryField::zero_b128();
        assert_eq!(b.field_add(&zero128), b);
        
        // Same for Ghash
        let c = BinaryField::ghash(0x12);
        let zero_ghash = BinaryField::zero_ghash();
        assert_eq!(c.field_add(&zero_ghash), c);
    }
    
    #[test]
    fn test_shift_optimization() {
        // The controversial optimization - clear method names
        
        // Test B1 (simple case)
        let mut acc1 = BinaryField::zero_b1();
        let val1 = BinaryField::b1(1);
        let byte1: u8 = 0b00000001;  // LSB set
        let mask1 = BinaryField::mask_from_byte_b1(byte1);
        let masked1 = val1.bit_and(&mask1);
        acc1 = acc1.field_add(&masked1);
        
        let mut acc = BinaryField::zero_b64();
        let val = BinaryField::b64(0x1234567890ABCDEF);
        let byte: u8 = 0b10101010;
        
        // Create mask - explicit function name
        let mask = BinaryField::mask_from_byte_b64(byte);
        
        // Apply mask - bit_and is clearly NOT field multiplication
        let masked = val.bit_and(&mask);
        
        // Add to accumulator - field operation
        acc = acc.field_add(&masked);
        
        // Clear what each operation does
        
        // Test B128
        let mut acc128 = BinaryField::zero_b128();
        let val128 = BinaryField::b128(0x1234567890ABCDEF1234567890ABCDEF);
        let mask128 = BinaryField::mask_from_byte_b128(byte);
        let masked128 = val128.bit_and(&mask128);
        acc128 = acc128.field_add(&masked128);
        
        // Test Ghash
        let mut acc_ghash = BinaryField::zero_ghash();
        let val_ghash = BinaryField::ghash(0x1234567890ABCDEF1234567890ABCDEF);
        let mask_ghash = BinaryField::mask_from_byte_ghash(byte);
        let masked_ghash = val_ghash.bit_and(&mask_ghash);
        acc_ghash = acc_ghash.field_add(&masked_ghash);
        
        // Use the variables
        let _ = (acc1, acc, acc128, acc_ghash);
    }
    
    #[test]
    fn test_mixed_operations() {
        // Mixing field and bit operations
        
        // Test B1
        let a1 = BinaryField::b1(1);
        let b1 = BinaryField::b1(1);
        let mask1 = BinaryField::b1(1);
        let product1 = a1.field_mul(&b1);  // 1 * 1 = 1
        let masked1 = product1.bit_and(&mask1);  // 1 & 1 = 1
        let _result1 = masked1.field_add(&BinaryField::b1(1));  // 1 + 1 = 0 in GF(2)
        
        let a = BinaryField::b64(0xAAAA);
        let b = BinaryField::b64(0xBBBB);
        let mask = BinaryField::b64(0xFF00);
        
        // Field multiplication
        let product = a.field_mul(&b);
        
        // Bitwise masking - explicitly different from field_mul
        let masked = product.bit_and(&mask);
        
        // Field addition
        let _result = masked.field_add(&BinaryField::b64(0x1111));
        
        // Method names make intent clear
        
        // Test B128
        let a128 = BinaryField::b128(0xAAAA);
        let b128 = BinaryField::b128(0xBBBB);
        let mask128 = BinaryField::b128(0xFF00);
        let product128 = a128.field_mul(&b128);
        let masked128 = product128.bit_and(&mask128);
        let _result128 = masked128.field_add(&BinaryField::b128(0x1111));
        
        // Test Ghash
        let a_ghash = BinaryField::ghash(0xAAAA);
        let b_ghash = BinaryField::ghash(0xBBBB);
        let mask_ghash = BinaryField::ghash(0xFF00);
        let product_ghash = a_ghash.field_mul(&b_ghash);
        let masked_ghash = product_ghash.bit_and(&mask_ghash);
        let _result_ghash = masked_ghash.field_add(&BinaryField::ghash(0x1111));
    }
    
    #[test]
    #[should_panic(expected = "Type mismatch")]
    fn test_type_mismatch_detection() {
        // Show that we detect type mismatches at runtime
        let a = BinaryField::b64(0x12);
        let b = BinaryField::b128(0x34);
        
        // This will panic - can't add different types
        let _ = a.field_add(&b);
    }
}