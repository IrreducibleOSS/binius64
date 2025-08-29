//! Comprehensive tests for constraint generation

use binius_beamish::*;
use binius_beamish::types::{Field64, U32, U64};

#[test]
#[should_panic(expected = "Cannot generate constraints for expression")]
fn xor_chain_panics() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let c = val::<Field64>(2);
    let expr = xor4(&a, &b, &c, &val(3));
    let _ = to_constraints(&expr);
}

#[test]
#[should_panic(expected = "Cannot generate constraints for expression")]
fn rotation_xor_panics() {
    let v = val::<U32>(0);
    let expr = xor3(&ror(&v, 7), &ror(&v, 18), &shr(&v, 3));
    let _ = to_constraints(&expr);
}

#[test]
fn and_operation_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let expr = and(&a, &b);
    let constraints = to_constraints(&expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn or_operation_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let expr = or(&a, &b);
    let constraints = to_constraints(&expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn addition_succeeds() {
    let x = val::<U32>(0);
    let y = val::<U32>(1);
    let expr = add(&x, &y);
    let constraints = to_constraints(&expr);
    assert_eq!(constraints.len(), 2); // Carry propagation + result
}

#[test]
fn multiplication_succeeds() {
    let x = val::<U64>(0);
    let y = val::<U64>(1);
    let expr = mul64(&x, &y);
    let constraints = to_constraints(&expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn keccak_chi_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let c = val::<Field64>(2);
    let expr = keccak_chi(&a, &b, &c);
    let constraints = to_constraints(&expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn multiplexer_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let c = val::<Field64>(2);
    let expr = mux(&a, &b, &c);
    let constraints = to_constraints(&expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn xor_with_equality_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let c = val::<Field64>(2);
    let xor_expr = xor(&a, &b);
    let eq_expr = eq(&c, &xor_expr);
    let constraints = to_constraints(&eq_expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn not_with_equality_succeeds() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let not_expr = not(&a);
    let eq_expr = eq(&b, &not_expr);
    let constraints = to_constraints(&eq_expr);
    assert_eq!(constraints.len(), 1);
}

#[test]
fn rotation_with_equality_succeeds() {
    let v = val::<U32>(0);
    let w = val::<U32>(1);
    let rot_expr = ror(&v, 7);
    let eq_expr = eq(&w, &rot_expr);
    let constraints = to_constraints(&eq_expr);
    assert_eq!(constraints.len(), 1);
}