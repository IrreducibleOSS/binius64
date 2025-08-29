//! Tests for panic behavior when expressions can't be constrained

use binius_beamish::*;
use binius_beamish::types::Field64;

#[test]
#[should_panic(expected = "Cannot generate constraints for expression")]
fn test_pure_xor_panics() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let xor_only = xor(&a, &b);
    
    // This should panic
    let _constraints = to_constraints(&xor_only);
}

#[test]
#[should_panic(expected = "Cannot generate constraints for expression")]
fn test_pure_not_panics() {
    let a = val::<Field64>(0);
    let not_expr = not(&a);
    
    // This should panic
    let _constraints = to_constraints(&not_expr);
}

#[test]
#[should_panic(expected = "Cannot generate constraints for expression")]
fn test_pure_rotation_panics() {
    use binius_beamish::types::U32;
    
    let v = val::<U32>(0);
    let rot_expr = ror(&v, 7);
    
    // This should panic
    let _constraints = to_constraints(&rot_expr);
}

#[test]
fn test_and_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let and_expr = and(&a, &b);
    
    let constraints = to_constraints(&and_expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn test_xor_with_equality_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let c = val::<Field64>(2);
    let xor_expr = xor(&a, &b);
    let eq_expr = eq(&c, &xor_expr);
    
    let constraints = to_constraints(&eq_expr);
    assert_eq!(constraints.len(), 1);
}