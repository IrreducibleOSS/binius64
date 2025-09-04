//! Bitwise operations using Call nodes

use crate::expr::{Expr, ExprNode};
use crate::types::BitType;
use std::rc::Rc;

/// Bitwise XOR
pub fn xor<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("xor needs 2 inputs") };
            a ^ b
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// Bitwise AND
pub fn and<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("and needs 2 inputs") };
            a & b
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// Bitwise OR  
pub fn or<T: BitType>(a: &Expr<T>, b: &Expr<T>) -> Expr<T> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("or needs 2 inputs") };
            a | b
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }))
}

/// Bitwise NOT
pub fn not<T: BitType>(a: &Expr<T>) -> Expr<T> {
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a] = inputs else { panic!("not needs 1 input") };
            !a
        },
        inputs: vec![a.inner.clone()],
    }))
}

/// Logical shift left
pub fn shl<T: BitType>(a: &Expr<T>, amount: u8) -> Expr<T> {
    let amount_expr = crate::expr::constant::<T>(amount as u64);
    
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, amount] = inputs else { panic!("shl needs 2 inputs") };
            a << (*amount as u8)
        },
        inputs: vec![a.inner.clone(), amount_expr.inner],
    }))
}

/// Logical shift right
pub fn shr<T: BitType>(a: &Expr<T>, amount: u8) -> Expr<T> {
    let amount_expr = crate::expr::constant::<T>(amount as u64);
    
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, amount] = inputs else { panic!("shr needs 2 inputs") };
            a >> (*amount as u8)
        },
        inputs: vec![a.inner.clone(), amount_expr.inner],
    }))
}

/// Arithmetic shift right  
pub fn sar<T: BitType>(a: &Expr<T>, amount: u8) -> Expr<T> {
    let amount_expr = crate::expr::constant::<T>(amount as u64);
    
    Expr::wrap(Rc::new(ExprNode::Call {
        compute: |inputs| {
            let [a, amount] = inputs else { panic!("sar needs 2 inputs") };
            let amt = *amount as u8;
            if T::BITS == 32 {
                ((*a as i32) >> amt) as u32 as u64
            } else {
                ((*a as i64) >> amt) as u64
            }
        },
        inputs: vec![a.inner.clone(), amount_expr.inner],
    }))
}