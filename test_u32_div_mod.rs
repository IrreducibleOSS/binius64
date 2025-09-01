//! Test u32 division and modulo operations

use binius_beamish::*;
use binius_beamish::types::U32;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::arithmetic::{udiv32, umod32};

fn main() {
    println!("Testing 32-bit udiv32 and umod32 operations");
    
    let test_cases = vec![
        (20u32, 3u32),      // 20 = 6*3 + 2  
        (100u32, 7u32),     // 100 = 14*7 + 2
        (u32::MAX, 7u32),   // Large number
    ];
    
    for (dividend, divisor) in test_cases {
        println!("\n--- Testing {} ÷ {} (32-bit) ---", dividend, divisor);
        
        let a = val::<U32>(0);
        let b = val::<U32>(1);
        
        let div_expr = udiv32(&a, &b);
        let mod_expr = umod32(&a, &b);
        
        let mut evaluator = ExpressionEvaluator::new(vec![dividend as u64, divisor as u64]);
        
        let quotient = evaluator.evaluate(&div_expr) as u32;
        let remainder = evaluator.evaluate(&mod_expr) as u32;
        
        let expected_quotient = dividend / divisor;
        let expected_remainder = dividend % divisor;
        
        println!("  {} = {} * {} + {}", dividend, quotient, divisor, remainder);
        println!("  Expected: {} = {} * {} + {}", dividend, expected_quotient, divisor, expected_remainder);
        
        let reconstructed = quotient * divisor + remainder;
        
        if reconstructed == dividend && quotient == expected_quotient && remainder == expected_remainder {
            println!("  ✓ CORRECT");
        } else {
            println!("  ✗ WRONG");
        }
    }
}