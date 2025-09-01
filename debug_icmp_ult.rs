//! Debug icmp_ult step by step

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::ops::conditional::icmp_ult;

fn main() {
    let a_val = 5u64;
    let b_val = 10u64;
    println!("Debugging {} < {} (should be true)", a_val, b_val);
    
    // Manual computation
    let not_a = !a_val;
    let (sum, carry) = not_a.overflowing_add(b_val);
    println!("  not_a = !{} = {}", a_val, not_a);
    println!("  not_a + {} = {} (carry: {})", b_val, sum, carry);
    
    let bout_expected = if carry { 0x8000_0000_0000_0000u64 } else { 0 };
    println!("  bout should be: 0x{:016x}", bout_expected);
    
    let sar_expected = ((bout_expected as i64) >> 63) as u64;
    println!("  bout >> 63 should be: 0x{:016x}", sar_expected);
    
    // Now test our implementation
    println!("\n--- Testing implementation ---");
    let a = val::<U64>(0);
    let b = val::<U64>(1);
    let result_expr = icmp_ult(&a, &b);
    
    let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
    let result = evaluator.evaluate(&result_expr);
    println!("  Actual result: 0x{:016x}", result);
    
    if result == u64::MAX {
        println!("  ✓ CORRECT");
    } else {
        println!("  ✗ WRONG");
    }
}