//! Arithmetic operation combinators

use crate::expr::{Expr, ExprNode};
use crate::types::{U32, U64};

// 32-bit arithmetic

/// 32-bit unsigned addition
pub fn add(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    Expr::new(ExprNode::Add32(a.inner.clone(), b.inner.clone()))
}

/// 32-bit unsigned subtraction
pub fn sub(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    Expr::new(ExprNode::Sub32(a.inner.clone(), b.inner.clone()))
}

/// 32-bit unsigned multiplication
pub fn mul(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    Expr::new(ExprNode::Mul32(a.inner.clone(), b.inner.clone()))
}

// 64-bit arithmetic

/// 64-bit unsigned addition
pub fn add64(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    Expr::new(ExprNode::Add64(a.inner.clone(), b.inner.clone()))
}

/// 64-bit unsigned subtraction  
pub fn sub64(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    Expr::new(ExprNode::Sub64(a.inner.clone(), b.inner.clone()))
}

/// 64-bit unsigned multiplication
pub fn mul64(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    Expr::new(ExprNode::Mul64(a.inner.clone(), b.inner.clone()))
}

// Method-style operations for U32
impl Expr<U32> {
    /// Add another U32 expression
    pub fn add(&self, other: &Expr<U32>) -> Expr<U32> {
        add(self, other)
    }
    
    /// Subtract another U32 expression
    pub fn sub(&self, other: &Expr<U32>) -> Expr<U32> {
        sub(self, other)
    }
    
    /// Multiply by another U32 expression
    pub fn mul(&self, other: &Expr<U32>) -> Expr<U32> {
        mul(self, other)
    }
}

// Method-style operations for U64
impl Expr<U64> {
    /// Add another U64 expression
    pub fn add(&self, other: &Expr<U64>) -> Expr<U64> {
        add64(self, other)
    }
    
    /// Subtract another U64 expression
    pub fn sub(&self, other: &Expr<U64>) -> Expr<U64> {
        sub64(self, other)
    }
    
    /// Multiply by another U64 expression
    pub fn mul(&self, other: &Expr<U64>) -> Expr<U64> {
        mul64(self, other)
    }
}