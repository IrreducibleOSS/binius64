//! Test icmp_eq implementation

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::conditional::icmp_eq;

fn main() {
    println!("Testing icmp_eq implementation");
    
    let test_cases = vec![
        (5u64, 10u64, false),   // different values
        (7u64, 7u64, true),     // same values
        (0u64, 0u64, true),     // zero case
        (u64::MAX, u64::MAX, true), // max value case
        (u64::MAX, 0u64, false), // max vs zero
    ];
    
    for (a_val, b_val, expected_eq) in test_cases {
        println!("\n--- Testing {} vs {} (should be equal: {}) ---", a_val, b_val, expected_eq);
        
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        
        // Test equality
        let eq_expr = icmp_eq(&a, &b);
        
        let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
        let eq_result = evaluator.evaluate(&eq_expr);
        
        let eq_bool = eq_result == u64::MAX;
        
        println!("  icmp_eq({}, {}) = 0x{:016x} -> {}", a_val, b_val, eq_result, eq_bool);
        
        if eq_bool == expected_eq {
            println!("  ✓ CORRECT");
        } else {
            println!("  ✗ WRONG (expected {})", expected_eq);
        }
    }
    
    println!("\n=== Testing both icmp_eq and icmp_ult together ===");
    
    let a = val::<U64>(0);
    let b = val::<U64>(1);
    
    let lt_expr = crate::ops::conditional::icmp_ult(&a, &b);
    let eq_expr = icmp_eq(&a, &b);
    
    // Test case: 5 vs 10
    let mut evaluator = ExpressionEvaluator::new(vec![5u64, 10u64]);
    
    let lt_result = evaluator.evaluate(&lt_expr) == u64::MAX;
    let eq_result = evaluator.evaluate(&eq_expr) == u64::MAX;
    
    println!("5 < 10: {} (expected true)", lt_result);
    println!("5 == 10: {} (expected false)", eq_result);
    
    // Test case: 7 vs 7
    let mut evaluator2 = ExpressionEvaluator::new(vec![7u64, 7u64]);
    
    let lt_result2 = evaluator2.evaluate(&lt_expr) == u64::MAX;
    let eq_result2 = evaluator2.evaluate(&eq_expr) == u64::MAX;
    
    println!("7 < 7: {} (expected false)", lt_result2);
    println!("7 == 7: {} (expected true)", eq_result2);
}