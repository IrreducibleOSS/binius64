//! Simple test for icmp_ult with BlackBox implementation

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::conditional::icmp_ult;
use binius_beamish::optimize::OptConfig;

fn main() {
    println!("Testing icmp_ult with BlackBox implementation");
    
    // Test 1: Basic functionality
    let test_cases = vec![
        (5u64, 10u64, true),   // 5 < 10 = true
        (10u64, 5u64, false),  // 10 < 5 = false
        (7u64, 7u64, false),   // 7 < 7 = false
        (0u64, 1u64, true),    // 0 < 1 = true
        (u64::MAX, 0u64, false), // MAX < 0 = false
    ];
    
    for (a_val, b_val, expected) in test_cases {
        println!("\nTesting {} < {} (expected: {})", a_val, b_val, expected);
        
        // Create expressions
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        let result_expr = icmp_ult(&a, &b);
        
        // Evaluate
        let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
        let result = evaluator.evaluate(&result_expr);
        
        let actual = result == u64::MAX;
        println!("  Result: 0x{:016x} -> {}", result, actual);
        
        if actual == expected {
            println!("  ✓ PASS");
        } else {
            println!("  ✗ FAIL");
        }
    }
    
    // Test 2: Constraint generation
    println!("\n--- Constraint Generation Test ---");
    let a = val::<U64>(0);
    let b = val::<U64>(1);
    let result_expr = icmp_ult(&a, &b);
    
    let constraints = to_constraints(&result_expr.cast::<binius_beamish::types::Field64>(), &OptConfig::default());
    println!("Generated {} constraints", constraints.len());
    
    // We expect around 2-3 constraints from the verification logic
    if constraints.len() < 10 {  // Reasonable upper bound
        println!("✓ Reasonable constraint count");
    } else {
        println!("⚠ Many constraints generated: {}", constraints.len());
    }
    
    println!("\nTest completed!");
}