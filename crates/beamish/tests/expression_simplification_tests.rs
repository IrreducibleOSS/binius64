//! Tests for expression simplification optimizations
//! These simplify the expression tree but generate the same number of constraints

use binius_beamish::*;
use binius_beamish::types::Field64;
use binius_beamish::optimize::OptConfig;

/// Helper to test expression simplification
fn test_simplification(
    name: &str,
    build_expr: fn() -> Expr<Field64>,
    enable_opt: fn(&mut OptConfig),
    expected_constraints: usize,
) {
    let expr = build_expr();
    
    // Without optimization
    let config_without = OptConfig::none_enabled();
    let constraints_without = to_constraints(&expr, &config_without);
    
    // With optimization
    let mut config_with = OptConfig::none_enabled();
    enable_opt(&mut config_with);
    let constraints_with = to_constraints(&expr, &config_with);
    
    println!("{}: simplifies expression ({}→{} constraints)", 
        name, constraints_without.len(), constraints_with.len());
    
    assert_eq!(constraints_without.len(), expected_constraints);
    assert_eq!(constraints_with.len(), expected_constraints);
}

/// Test XOR self-elimination: x ⊕ x → 0
#[test]
fn test_xor_self_elimination() {
    test_simplification(
        "XOR Self-Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &xor(&a, &a))
        },
        |c| c.xor_self_elimination = true,
        1,  // Both generate single equality constraint
    );
}

/// Test XOR zero elimination: x ⊕ 0 → x
#[test]
fn test_xor_zero_elimination() {
    test_simplification(
        "XOR Zero Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &xor(&a, &constant(0)))
        },
        |c| c.xor_zero_elimination = true,
        1,  // Both generate single equality constraint
    );
}

/// Test XOR ones elimination: x ⊕ 1* → ~x
#[test]
fn test_xor_ones_elimination() {
    test_simplification(
        "XOR Ones Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &xor(&a, &constant(0xFFFFFFFFFFFFFFFF)))
        },
        |c| c.xor_ones_elimination = true,
        1,  // Both generate single equality constraint
    );
}

/// Test XOR term cancellation: (a⊕b)⊕(a⊕c) → b⊕c
#[test]
fn test_xor_term_cancellation() {
    test_simplification(
        "XOR Term Cancellation",
        || {
            let a = val::<Field64>(0);
            let b = val::<Field64>(1);
            let c = val::<Field64>(2);
            let result = val::<Field64>(3);
            
            // (a⊕b)⊕(a⊕c) should become b⊕c
            let ab = xor(&a, &b);
            let ac = xor(&a, &c);
            let complex = xor(&ab, &ac);
            eq(&result, &complex)
        },
        |c| c.xor_term_cancellation = true,
        1,  // Both generate single equality constraint
    );
}

/// Test double NOT elimination: ~~x → x
#[test]
fn test_double_not_elimination() {
    test_simplification(
        "Double NOT Elimination",
        || {
            let a = val::<Field64>(0);
            let result = val::<Field64>(1);
            eq(&result, &not(&not(&a)))
        },
        |c| c.double_not_elimination = true,
        1,  // Both generate single equality constraint
    );
}

/// Test NOT constant elimination: ~0 → 1*, ~1* → 0
#[test]
fn test_not_const_elimination() {
    test_simplification(
        "NOT Constant Elimination",
        || {
            let result = val::<Field64>(0);
            eq(&result, &not(&constant(0)))
        },
        |c| c.not_const_elimination = true,
        1,  // Both generate single equality constraint
    );
}

/// Test common subexpression elimination
#[test]
fn test_cse() {
    let a = val::<Field64>(0);
    let b = val::<Field64>(1);
    let c = val::<Field64>(2);
    let result = val::<Field64>(3);
    
    // Create expression with repeated subexpression (a ⊕ b)
    let ab1 = xor(&a, &b);
    let ab2 = xor(&a, &b);  // Same subexpression
    let expr1 = and(&ab1, &c);
    let expr2 = and(&ab2, &c);
    let final_expr = xor(&expr1, &expr2);
    let expr = eq(&result, &final_expr);
    
    let config_without = OptConfig::none_enabled();
    let mut config_with = OptConfig::none_enabled();
    config_with.cse_enabled = true;
    
    let unopt = to_constraints(&expr, &config_without);
    let opt = to_constraints(&expr, &config_with);
    
    println!("Common Subexpression Elimination: {} constraints", opt.len());
    
    // CSE should reduce constraints by reusing (a ⊕ b)
    assert!(opt.len() <= unopt.len());
}