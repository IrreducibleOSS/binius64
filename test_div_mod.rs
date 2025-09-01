//! Test udiv and umod together

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::arithmetic::{udiv, umod};

fn main() {
    println!("Testing udiv and umod together");
    
    let test_cases = vec![
        (20u64, 3u64),        // 20 = 6*3 + 2
        (100u64, 7u64),       // 100 = 14*7 + 2
        (42u64, 5u64),        // 42 = 8*5 + 2
        (1000u64, 13u64),     // 1000 = 76*13 + 12
        (u64::MAX, 7u64),     // Large number
    ];
    
    for (dividend, divisor) in test_cases {
        println!("\n--- Testing {} ÷ {} ---", dividend, divisor);
        
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        
        let div_expr = udiv(&a, &b);
        let mod_expr = umod(&a, &b);
        
        let mut evaluator = ExpressionEvaluator::new(vec![dividend, divisor]);
        
        let quotient = evaluator.evaluate(&div_expr);
        let remainder = evaluator.evaluate(&mod_expr);
        
        // Verify the division identity: dividend = quotient * divisor + remainder
        let reconstructed = quotient * divisor + remainder;
        
        println!("  {} = {} * {} + {}", dividend, quotient, divisor, remainder);
        println!("  Reconstructed: {}", reconstructed);
        
        if reconstructed == dividend && remainder < divisor {
            println!("  ✓ CORRECT (division identity holds and remainder < divisor)");
        } else {
            println!("  ✗ WRONG");
            if reconstructed != dividend {
                println!("    Division identity failed!");
            }
            if remainder >= divisor {
                println!("    Remainder {} >= divisor {}!", remainder, divisor);
            }
        }
    }
    
    // Test composition with other operations
    println!("\n=== Composition Tests ===");
    
    let a = val::<U64>(0);  // 25
    let b = val::<U64>(1);  // 7
    
    // Test: (a / b) + (a % b) 
    let div_result = udiv(&a, &b);
    let mod_result = umod(&a, &b);
    let sum_expr = crate::ops::arithmetic::add64(&div_result, &mod_result);
    
    let mut evaluator = ExpressionEvaluator::new(vec![25u64, 7u64]);
    let sum_result = evaluator.evaluate(&sum_expr);
    
    // 25/7 = 3, 25%7 = 4, so 3+4 = 7
    println!("(25 / 7) + (25 % 7) = {}", sum_result);
    
    if sum_result == 7 {
        println!("✓ Composition with addition works");
    } else {
        println!("✗ Composition failed");
    }
}