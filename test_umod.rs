//! Test umod implementation

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::arithmetic::umod;

fn main() {
    println!("Testing umod implementation");
    
    let test_cases = vec![
        (20u64, 4u64, 0u64),        // Even division
        (17u64, 3u64, 2u64),        // Division with remainder
        (100u64, 7u64, 2u64),       // Larger remainder
        (42u64, 42u64, 0u64),       // Equal values
        (7u64, 10u64, 7u64),        // Smaller dividend
        (u64::MAX, 3u64, (u64::MAX % 3)),  // Large values
        (0u64, 5u64, 0u64),         // Zero dividend
        (42u64, 0u64, 0u64),        // Modulo by zero (should return 0)
        (1000u64, 13u64, 12u64),    // Another test case
    ];
    
    for (a_val, b_val, expected) in test_cases {
        println!("\n--- Testing {} % {} ---", a_val, b_val);
        
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        let mod_expr = umod(&a, &b);
        
        let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
        let result = evaluator.evaluate(&mod_expr);
        
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
    let const_17 = constant::<U64>(17);
    let const_5 = constant::<U64>(5);
    let mod_const = umod(&const_17, &const_5);
    
    let mut evaluator = ExpressionEvaluator::new(vec![]);
    let const_result = evaluator.evaluate(&mod_const);
    
    println!("Constant modulo 17%5: {} (expected 2)", const_result);
    
    if const_result == 2 {
        println!("✓ Constant modulo works");
    } else {
        println!("✗ Constant modulo failed");
    }
}