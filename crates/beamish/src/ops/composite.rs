//! Composite operations built from primitives

use crate::expr::{Expr, ExprNode};
use crate::ops::{xor, and, not};
use crate::types::{BitType, U32};

/// Three-way XOR (common in crypto)
pub fn xor3<T: BitType>(a: &Expr<T>, b: &Expr<T>, c: &Expr<T>) -> Expr<T> {
    xor(&xor(a, b), c)
}

/// Four-way XOR
pub fn xor4<T: BitType>(a: &Expr<T>, b: &Expr<T>, c: &Expr<T>, d: &Expr<T>) -> Expr<T> {
    xor(&xor(&xor(a, b), c), d)
}

/// N-way XOR
pub fn xor_many<T: BitType>(exprs: &[Expr<T>]) -> Expr<T> {
    exprs.iter()
        .skip(1)
        .fold(exprs[0].clone(), |acc, e| xor(&acc, e))
}

/// SHA-256 Ch function: (a ∧ b) ⊕ (¬a ∧ c)
pub fn ch<T: BitType>(a: &Expr<T>, b: &Expr<T>, c: &Expr<T>) -> Expr<T> {
    xor(
        &and(a, b),
        &and(&not(a), c)
    )
}

/// SHA-256 Maj function: (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
pub fn maj<T: BitType>(a: &Expr<T>, b: &Expr<T>, c: &Expr<T>) -> Expr<T> {
    xor3(
        &and(a, b),
        &and(a, c),
        &and(b, c)
    )
}

/// Multiplexer: cond ? true_val : false_val
pub fn mux<T>(cond: &Expr<T>, true_val: &Expr<T>, false_val: &Expr<T>) -> Expr<T> {
    Expr::new(ExprNode::Mux(
        cond.inner.clone(),
        true_val.inner.clone(),
        false_val.inner.clone()
    ))
}

/// Conditional select (same as mux but clearer name)
pub fn select<T>(cond: &Expr<T>, if_true: &Expr<T>, if_false: &Expr<T>) -> Expr<T> {
    mux(cond, if_true, if_false)
}

// SHA-256 specific functions
use crate::ops::{ror, shr, add};

/// SHA-256 Σ0 (Sigma0) for message schedule
pub fn sha256_sigma0(x: &Expr<U32>) -> Expr<U32> {
    xor3(
        &ror(x, 7),
        &ror(x, 18),
        &shr(x, 3)
    )
}

/// SHA-256 Σ1 (Sigma1) for message schedule
pub fn sha256_sigma1(x: &Expr<U32>) -> Expr<U32> {
    xor3(
        &ror(x, 17),
        &ror(x, 19),
        &shr(x, 10)
    )
}

/// SHA-256 Σ0 (big Sigma0) for compression
pub fn sha256_big_sigma0(x: &Expr<U32>) -> Expr<U32> {
    xor3(
        &ror(x, 2),
        &ror(x, 13),
        &ror(x, 22)
    )
}

/// SHA-256 Σ1 (big Sigma1) for compression
pub fn sha256_big_sigma1(x: &Expr<U32>) -> Expr<U32> {
    xor3(
        &ror(x, 6),
        &ror(x, 11),
        &ror(x, 25)
    )
}

/// Add multiple U32 values
pub fn add_many(exprs: &[Expr<U32>]) -> Expr<U32> {
    exprs.iter()
        .skip(1)
        .fold(exprs[0].clone(), |acc, e| add(&acc, e))
}

// Keccak specific patterns

/// Keccak chi: a ⊕ ((¬b) ∧ c)
pub fn keccak_chi<T: BitType>(a: &Expr<T>, b: &Expr<T>, c: &Expr<T>) -> Expr<T> {
    xor(a, &and(&not(b), c))
}