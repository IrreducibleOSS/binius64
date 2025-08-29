//! Bitwise operation combinators

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
}