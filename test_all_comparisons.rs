//! Test all comparison operations

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::conditional::*;

fn main() {
    println!("Testing all unsigned comparison operations");
    
    let test_cases = vec![
        (5u64, 10u64),   // 5 vs 10
        (10u64, 5u64),   // 10 vs 5
        (7u64, 7u64),    // 7 vs 7 (equal)
        (0u64, 1u64),    // edge case: 0 vs 1
        (u64::MAX, 0u64), // edge case: max vs 0
    ];
    
    for (a_val, b_val) in test_cases {
        println!("\n--- Testing {} vs {} ---", a_val, b_val);
        
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        
        // Test all comparisons
        let lt_expr = icmp_ult(&a, &b);   // a < b
        let le_expr = icmp_ule(&a, &b);   // a <= b  
        let gt_expr = icmp_ugt(&a, &b);   // a > b
        let ge_expr = icmp_uge(&a, &b);   // a >= b
        let eq_expr = icmp_eq(&a, &b);    // a == b
        let ne_expr = icmp_ne(&a, &b);    // a != b
        
        let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
        
        let lt_result = evaluator.evaluate(&lt_expr) == u64::MAX;
        let le_result = evaluator.evaluate(&le_expr) == u64::MAX;
        let gt_result = evaluator.evaluate(&gt_expr) == u64::MAX;
        let ge_result = evaluator.evaluate(&ge_expr) == u64::MAX;
        let eq_result = evaluator.evaluate(&eq_expr) == u64::MAX;
        let ne_result = evaluator.evaluate(&ne_expr) == u64::MAX;
        
        // Expected results
        let exp_lt = a_val < b_val;
        let exp_le = a_val <= b_val;
        let exp_gt = a_val > b_val;
        let exp_ge = a_val >= b_val;
        let exp_eq = a_val == b_val;
        let exp_ne = a_val != b_val;
        
        println!("  {} <  {} : {} (expected {})", a_val, b_val, lt_result, exp_lt);
        println!("  {} <= {} : {} (expected {})", a_val, b_val, le_result, exp_le);
        println!("  {} >  {} : {} (expected {})", a_val, b_val, gt_result, exp_gt);
        println!("  {} >= {} : {} (expected {})", a_val, b_val, ge_result, exp_ge);
        println!("  {} == {} : {} (expected {})", a_val, b_val, eq_result, exp_eq);
        println!("  {} != {} : {} (expected {})", a_val, b_val, ne_result, exp_ne);
        
        // Verify all results
        let all_correct = 
            lt_result == exp_lt &&
            le_result == exp_le &&
            gt_result == exp_gt &&
            ge_result == exp_ge &&
            eq_result == exp_eq &&
            ne_result == exp_ne;
            
        if all_correct {
            println!("  ✓ ALL CORRECT");
        } else {
            println!("  ✗ SOME INCORRECT");
        }
    }
}