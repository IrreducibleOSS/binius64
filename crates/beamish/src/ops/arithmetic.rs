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

/// 32-bit unsigned division
///
/// Returns `a / b` using unsigned division.
/// 
/// # Implementation
/// Uses a BlackBox to compute the division result.
/// Division by zero returns 0 (following Rust's wrapping division semantics).
pub fn udiv32(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    use crate::expr::ExprNode;
    
    Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("udiv32 needs 2 inputs") };
            if *b == 0 { 0 } else { a / b }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 32-bit unsigned modulo
///
/// Returns `a % b` using unsigned modulo.
/// 
/// # Implementation
/// Uses a BlackBox to compute the modulo result.
/// Modulo by zero returns 0 (following Rust's wrapping modulo semantics).
pub fn umod32(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    use crate::expr::ExprNode;
    
    Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("umod32 needs 2 inputs") };
            if *b == 0 { 0 } else { a % b }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
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

/// 64-bit unsigned division
///
/// Returns `a / b` using unsigned division.
/// 
/// # Implementation
/// Uses a BlackBox to compute the division result.
/// Division by zero returns 0 (following Rust's wrapping division semantics).
pub fn udiv(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    use crate::expr::ExprNode;
    
    Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("udiv needs 2 inputs") };
            if *b == 0 { 0 } else { a / b }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 64-bit unsigned modulo
///
/// Returns `a % b` using unsigned modulo.
/// 
/// # Implementation
/// Uses a BlackBox to compute the modulo result.
/// Modulo by zero returns 0 (following Rust's wrapping modulo semantics).
pub fn umod(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    use crate::expr::ExprNode;
    
    Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("umod needs 2 inputs") };
            if *b == 0 { 0 } else { a % b }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

// Note: Method-style operations removed as they don't work well with value-based API
// Use the free functions instead: add(a, b) rather than a.add(b)