//! Comparison operations using Call nodes

use crate::expr::{Expr, ExprNode};
use crate::types::{BitType, U32, U64};
use std::rc::Rc;

/// Generic equality comparison (free - uses XOR + NOT)
pub fn icmp_eq<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    use super::bitwise::{xor, not};
    not(&xor(a, b))
}

/// 32-bit unsigned less-than
pub fn icmp_ult32(a: &Expr<U32>, b: &Expr<U32>) -> Expr<U32> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("icmp_ult32 needs 2 inputs") };
            if (*a as u32) < (*b as u32) {
                u32::MAX as u64  // All 1s for true
            } else {
                0  // All 0s for false
            }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// 64-bit unsigned less-than
pub fn icmp_ult64(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("icmp_ult64 needs 2 inputs") };
            if *a < *b {
                u64::MAX  // All 1s for true
            } else {
                0  // All 0s for false
            }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}