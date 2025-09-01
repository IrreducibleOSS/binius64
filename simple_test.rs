//! Simple test for SAR

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;

fn main() {
    // Test built-in SAR directly
    let msb_val = constant::<U64>(0x8000_0000_0000_0000);
    let sar_expr = sar(&msb_val, 63);
    
    let mut evaluator = ExpressionEvaluator::new(vec![]);
    let result = evaluator.evaluate(&sar_expr);
    
    println!("SAR(0x8000000000000000, 63) = 0x{:016x}", result);
    println!("Expected: 0xffffffffffffffff");
    println!("Match: {}", result == 0xffffffffffffffff);
    
    // Also test what 0x8000_0000_0000_0000 as i64 >> 63 gives
    let manual = ((0x8000_0000_0000_0000u64 as i64) >> 63) as u64;
    println!("Manual computation: 0x{:016x}", manual);
}