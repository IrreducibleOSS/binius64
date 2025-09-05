//! Bitwise operation combinators
//!
//! Includes XOR, AND, OR, NOT, shifts, rotations, and equality operations.

use crate::expr::{Expr, ExprNode};
use crate::types::BitType;

/// Bitwise XOR (field addition in GF(2^64))
pub fn xor<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    Expr::new(ExprNode::Xor(a.inner.clone(), b.inner.clone()))
}

/// Bitwise AND
pub fn and<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    Expr::new(ExprNode::And(a.inner.clone(), b.inner.clone()))
}

/// Bitwise OR
pub fn or<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    Expr::new(ExprNode::Or(a.inner.clone(), b.inner.clone()))
}

/// Bitwise NOT
pub fn not<T: BitType>(a: &Expr<T>) -> Expr<T> {
    Expr::new(ExprNode::Not(a.inner.clone()))
}

/// Logical shift left
pub fn shl<T: BitType>(expr: &Expr<T>, amount: u8) -> Expr<T> {
    Expr::new(ExprNode::Shl(expr.inner.clone(), amount))
}

/// Logical shift right
pub fn shr<T: BitType>(expr: &Expr<T>, amount: u8) -> Expr<T> {
    Expr::new(ExprNode::Shr(expr.inner.clone(), amount))
}

/// Arithmetic shift right (sign-extend)
pub fn sar<T: BitType>(expr: &Expr<T>, amount: u8) -> Expr<T> {
    Expr::new(ExprNode::Sar(expr.inner.clone(), amount))
}

/// 32-bit arithmetic shift right
/// 
/// Sign-extends from bit 31 for U32 values.
/// The evaluation will treat this as U32-specific.
pub fn sar32(expr: &Expr<crate::types::U32>, amount: u8) -> Expr<crate::types::U32> {
    sar(expr, amount)
}

/// Rotate left
pub fn rol<T: BitType>(expr: &Expr<T>, amount: u8) -> Expr<T> {
    Expr::new(ExprNode::Rol(expr.inner.clone(), amount))
}

/// Rotate right
pub fn ror<T: BitType>(expr: &Expr<T>, amount: u8) -> Expr<T> {
    Expr::new(ExprNode::Ror(expr.inner.clone(), amount))
}

/// Equality constraint: forces a = b
/// 
/// In Binius64, this generates: (a ⊕ b) ∧ 𝟙 ⊕ 0 = 0
/// This forces the two expressions to be equal.
pub fn eq<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    Expr::new(ExprNode::Equal(a.inner.clone(), b.inner.clone()))
}

/// Assert two expressions are equal (same as eq but clearer name)
pub fn assert_equal<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    eq(a, b)
}

/// 32-bit rotate right
/// 
/// Decomposes to: (x >> n) ^ (x << (32 - n))
/// The result will be masked to 32 bits during constraint generation
pub fn ror32(expr: &Expr<crate::types::U32>, amount: u8) -> Expr<crate::types::U32> {
    // Decompose rotation into shifts and XOR
    // The shifted ranges don't overlap:
    // - right_shifted occupies bits 0..(31-n)
    // - left_shifted occupies bits (32-n)..63
    // So OR = XOR, and masking happens at constraint boundary
    let right_shifted = shr(expr, amount);
    let left_shifted = shl(expr, 32 - amount);
    xor(&right_shifted, &left_shifted)
}

/// 32-bit shift right
/// 
/// Regular shift right works fine for U32 as long as input is masked to 32 bits
pub fn shr32(expr: &Expr<crate::types::U32>, amount: u8) -> Expr<crate::types::U32> {
    shr(expr, amount)
}

// Note: Method-style operations removed as they don't work well with value-based API
// Use the free functions instead: xor(a, b) rather than a.xor(b)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constant, types::{U32, U64}};
    use crate::compute::expressions::ExpressionEvaluator;
    
    #[test]
    fn test_sar_u32() {
        // Test U32 arithmetic shift with MSB set
        let val = constant::<U32>(0x80000000);
        let shifted = sar(&val, 31);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        let result = eval.evaluate(&shifted) as u32;
        
        assert_eq!(result, 0xffffffff, "U32 sar should sign-extend from bit 31");
    }
    
    #[test]
    fn test_sar_u32_positive() {
        // Test U32 arithmetic shift with positive value
        let val = constant::<U32>(0x40000000);
        let shifted = sar(&val, 31);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        let result = eval.evaluate(&shifted) as u32;
        
        assert_eq!(result, 0, "Positive U32 sar should shift to 0");
    }
    
    #[test]
    fn test_sar_u64() {
        // Test U64 arithmetic shift with MSB set
        let val = constant::<U64>(0x8000000000000000);
        let shifted = sar(&val, 63);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        let result = eval.evaluate(&shifted);
        
        assert_eq!(result, 0xffffffffffffffff, "U64 sar should sign-extend from bit 63");
    }
    
    #[test]
    fn test_sar_u64_positive() {
        // Test U64 arithmetic shift with positive value  
        let val = constant::<U64>(0x4000000000000000);
        let shifted = sar(&val, 63);
        
        let mut eval = ExpressionEvaluator::new(vec![]);
        let result = eval.evaluate(&shifted);
        
        assert_eq!(result, 0, "Positive U64 sar should shift to 0");
    }
}