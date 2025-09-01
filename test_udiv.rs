//! Test udiv implementation

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::arithmetic::udiv;

fn main() {
    println!("Testing udiv implementation");
    
    let test_cases = vec![
        (20u64, 4u64, 5u64),        // Basic division
        (17u64, 3u64, 5u64),        // Division with remainder
        (100u64, 1u64, 100u64),     // Divide by 1
        (42u64, 42u64, 1u64),       // Equal values
        (7u64, 10u64, 0u64),        // Smaller dividend
        (u64::MAX, 2u64, u64::MAX / 2),  // Large values
        (0u64, 5u64, 0u64),         // Zero dividend
        (42u64, 0u64, 0u64),        // Division by zero (should return 0)
    ];
    
    for (a_val, b_val, expected) in test_cases {
        println!("\n--- Testing {} / {} ---", a_val, b_val);
        
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        let div_expr = udiv(&a, &b);
        
        let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
        let result = evaluator.evaluate(&div_expr);
        
        println!("  Result: {}", result);
        println!("  Expected: {}", expected);
        
        if result == expected {
            println!("  ✓ CORRECT");
        } else {
            println!("  ✗ WRONG");
        }
    }
    
    // Test edge cases
    println!("\n=== Edge Case Tests ===");
    
    // Test with constants
    let const_20 = constant::<U64>(20);
    let const_4 = constant::<U64>(4);
    let div_const = udiv(&const_20, &const_4);
    
    let mut evaluator = ExpressionEvaluator::new(vec![]);
    let const_result = evaluator.evaluate(&div_const);
    
    println!("Constant division 20/4: {} (expected 5)", const_result);
    
    if const_result == 5 {
        println!("✓ Constant division works");
    } else {
        println!("✗ Constant division failed");
    }
}