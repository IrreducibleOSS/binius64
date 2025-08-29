//! Shift and rotation operation combinators

use crate::expr::{Expr, ExprNode};
use crate::types::BitType;

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

// Method-style operations for chaining
impl<T: BitType> Expr<T> {
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
}