//! Equality constraint operations

use crate::expr::{Expr, ExprNode};
use crate::types::BitType;

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

// Method-style operations
impl<T: BitType> Expr<T> {
    /// Assert this expression equals another
    pub fn equals(&self, other: &Expr<T>) -> Expr<T> {
        eq(self, other)
    }
}