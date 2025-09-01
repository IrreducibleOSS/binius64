//! Debug equality operations

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::conditional::{icmp_eq, icmp_ne};

fn main() {
    println!("Debugging equality operations");
    
    let test_cases = vec![
        (5u64, 10u64, false),   // different values
        (7u64, 7u64, true),     // same values
        (0u64, 0u64, true),     // zero case
    ];
    
    for (a_val, b_val, expected_eq) in test_cases {
        println!("\n--- Testing {} vs {} (should be equal: {}) ---", a_val, b_val, expected_eq);
        
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        
        // Test basic operations
        let xor_expr = xor(&a, &b);
        let not_xor_expr = not(&xor(&a, &b));
        let eq_expr = icmp_eq(&a, &b);
        let ne_expr = icmp_ne(&a, &b);
        
        let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
        
        let xor_result = evaluator.evaluate(&xor_expr);
        let not_xor_result = evaluator.evaluate(&not_xor_expr);
        let eq_result = evaluator.evaluate(&eq_expr);
        let ne_result = evaluator.evaluate(&ne_expr);
        
        println!("  a XOR b = 0x{:016x}", xor_result);
        println!("  NOT(a XOR b) = 0x{:016x}", not_xor_result);
        println!("  icmp_eq result = 0x{:016x}", eq_result);
        println!("  icmp_ne result = 0x{:016x}", ne_result);
        
        // Check if results match expectations
        let eq_correct = (eq_result == u64::MAX) == expected_eq;
        let ne_correct = (ne_result == u64::MAX) == !expected_eq;
        
        println!("  Equality correct: {} (got {}, expected {})", eq_correct, eq_result == u64::MAX, expected_eq);
        println!("  Inequality correct: {} (got {}, expected {})", ne_correct, ne_result == u64::MAX, !expected_eq);
    }
}