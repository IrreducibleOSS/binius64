//! Arithmetic operations using Call nodes
//!
//! All operations create Call nodes - the grains module handles constraint generation.

use crate::expr::{Expr, ExprNode};
use crate::types::{U32, U64};
use std::rc::Rc;

/// 32-bit addition
pub fn add(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("add needs 2 inputs") };
            ((*a as u32).wrapping_add(*b as u32)) as u64
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 32-bit subtraction  
pub fn sub(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("sub needs 2 inputs") };
            ((*a as u32).wrapping_sub(*b as u32)) as u64
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 32-bit multiplication
pub fn mul(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("mul needs 2 inputs") };
            ((*a as u32).wrapping_mul(*b as u32)) as u64
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 64-bit addition
pub fn add64(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("add64 needs 2 inputs") };
            a.wrapping_add(*b)
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 64-bit subtraction
pub fn sub64(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("sub64 needs 2 inputs") };
            a.wrapping_sub(*b)
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 64-bit multiplication
pub fn mul64(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("mul64 needs 2 inputs") };
            a.wrapping_mul(*b)
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}