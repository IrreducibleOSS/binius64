//! Tests for constraint generation validation
//! These test that the compiler generates expected constraints for various patterns

use binius_beamish::*;
use binius_beamish::types::{Field64, U32};
use binius_beamish::optimize::OptConfig;

/// Helper to combine multiple expressions with AND
fn and_all(exprs: &[Expr<Field64>]) -> Expr<Field64> {
    if exprs.is_empty() {
        constant(1)  // True
    } else if exprs.len() == 1 {
        exprs[0].clone()
    } else {
        let mut result = exprs[0].clone();
        for expr in &exprs[1..] {
            result = and(&result, expr);
        }
        result
    }
}

/// Test conditional pattern: (a&b) ⊕ ((~a)&c)
#[test]
fn test_conditional_pattern() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let c = val::<Field64>(2);
    let result = val::<Field64>(3);
    
    // (a&b) ⊕ ((~a)&c) pattern
    let cond1 = and(&a, &b);
    let cond2 = and(&not(&a), &c);
    let select = xor(&cond1, &cond2);
    let expr = eq(&result, &select);
    
    let constraints = to_constraints(&expr, &OptConfig::default());
    
    println!("Conditional Pattern: generates {} constraints", constraints.len());
    
    // With conditional_select_rewrite enabled by default, this optimizes to fewer constraints
    assert_eq!(constraints.len(), 2);
}

/// Test rotation-XOR pattern: (x>>>a) ⊕ (x>>>b) ⊕ (x>>>c)
#[test]
fn test_rotation_xor_pattern() {
    let x = val::<U32>(0);
    let result = val::<U32>(1);
    
    // Triple rotation-XOR pattern
    let r2 = ror(&x, 2);
    let r13 = ror(&x, 13);
    let r22 = ror(&x, 22);
    let rotation_xor = xor(&xor(&r2, &r13), &r22);
    let expr = eq(&result, &rotation_xor);
    
    let constraints = to_constraints(&expr, &OptConfig::default());
    
    println!("Rotation-XOR Pattern: generates {} constraint", constraints.len());
    
    // Rotation-XOR is native to Binius64
    assert_eq!(constraints.len(), 1);
}

/// Test XOR-AND-NOT pattern: x ⊕ ((~y) & z)
#[test]
fn test_xor_and_not_pattern() {
    let x = val::<Field64>(0);
    let y = val::<Field64>(1);
    let z = val::<Field64>(2);
    let result = val::<Field64>(10);
    
    // x ⊕ ((~y) & z) pattern
    let pattern = xor(&x, &and(&not(&y), &z));
    let expr = eq(&result, &pattern);
    
    let constraints = to_constraints(&expr, &OptConfig::default());
    
    println!("XOR-AND-NOT Pattern: generates {} constraints", constraints.len());
    
    assert_eq!(constraints.len(), 2);
}

/// Test multiple XOR-AND-NOT patterns
#[test]
fn test_multiple_xor_and_not_patterns() {
    let v0 = val::<Field64>(0);
    let v1 = val::<Field64>(1);
    let v2 = val::<Field64>(2);
    let v3 = val::<Field64>(3);
    let v4 = val::<Field64>(4);
    
    let r0 = val::<Field64>(10);
    let r1 = val::<Field64>(11);
    let r2 = val::<Field64>(12);
    let r3 = val::<Field64>(13);
    let r4 = val::<Field64>(14);
    
    // Multiple XOR-AND-NOT patterns (circular references)
    let pattern0 = xor(&v0, &and(&not(&v1), &v2));
    let pattern1 = xor(&v1, &and(&not(&v2), &v3));
    let pattern2 = xor(&v2, &and(&not(&v3), &v4));
    let pattern3 = xor(&v3, &and(&not(&v4), &v0));
    let pattern4 = xor(&v4, &and(&not(&v0), &v1));
    
    let expr = and_all(&[
        eq(&r0, &pattern0),
        eq(&r1, &pattern1),
        eq(&r2, &pattern2),
        eq(&r3, &pattern3),
        eq(&r4, &pattern4),
    ]);
    
    let constraints = to_constraints(&expr, &OptConfig::default());
    
    println!("Multiple XOR-AND-NOT: generates {} constraints", constraints.len());
    
    // Each pattern creates constraints for the AND and the final equality
    assert!(constraints.len() <= 14);
}