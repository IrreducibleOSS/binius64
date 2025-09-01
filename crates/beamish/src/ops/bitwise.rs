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

/// Arithmetic shift right
pub fn sar<T: BitType>(expr: &Expr<T>, amount: u8) -> Expr<T> {
    Expr::new(ExprNode::Sar(expr.inner.clone(), amount))
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

// Method-style operations for chaining
impl<T: BitType> Expr<T> {
    /// XOR with another expression
    pub fn xor(&self, other: &Expr<T>) -> Expr<T> {
        xor(self, other)
    }
    
    /// AND with another expression
    pub fn and(&self, other: &Expr<T>) -> Expr<T> {
        and(self, other)
    }
    
    /// OR with another expression
    pub fn or(&self, other: &Expr<T>) -> Expr<T> {
        or(self, other)
    }
    
    /// NOT this expression
    pub fn not(&self) -> Expr<T> {
        not(self)
    }
    
    /// Logical shift left
    pub fn shl(&self, amount: u8) -> Expr<T> {
        shl(self, amount)
    }
    
    /// Logical shift right
    pub fn shr(&self, amount: u8) -> Expr<T> {
        shr(self, amount)
    }
    
    /// Arithmetic shift right
    pub fn sar(&self, amount: u8) -> Expr<T> {
        sar(self, amount)
    }
    
    /// Rotate left
    pub fn rol(&self, amount: u8) -> Expr<T> {
        rol(self, amount)
    }
    
    /// Rotate right
    pub fn ror(&self, amount: u8) -> Expr<T> {
        ror(self, amount)
    }
    
    /// Assert this expression equals another
    pub fn equals(&self, other: &Expr<T>) -> Expr<T> {
        eq(self, other)
    }
}