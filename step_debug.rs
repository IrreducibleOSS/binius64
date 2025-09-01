//! Step by step debug of icmp_ult

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::expr::{Expr, ExprNode};

fn main() {
    let a_val = 5u64;
    let b_val = 10u64;
    println!("Step-by-step debug of {} < {}", a_val, b_val);
    
    let a = val::<U64>(0);
    let b = val::<U64>(1);
    
    // Step 1: Create the BlackBox
    let bout = Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("icmp_ult needs 2 inputs") };
            let not_a = !a;
            let (_, carry) = not_a.overflowing_add(*b);
            let result = if carry { 0x8000_0000_0000_0000 } else { 0 };
            println!("  BlackBox compute: !{} + {} -> carry={}, result=0x{:016x}", a, b, carry, result);
            result
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }));
    
    println!("\nStep 1: Evaluating BlackBox");
    let mut evaluator1 = ExpressionEvaluator::new(vec![a_val, b_val]);
    let bout_val = evaluator1.evaluate(&bout);
    println!("  BlackBox result: 0x{:016x}", bout_val);
    
    // Step 2: Apply SAR to BlackBox result
    println!("\nStep 2: Applying SAR");
    let sar_expr = sar(&bout, 63);
    let mut evaluator2 = ExpressionEvaluator::new(vec![a_val, b_val]);
    let sar_val = evaluator2.evaluate(&sar_expr);
    println!("  SAR result: 0x{:016x}", sar_val);
    
    println!("\nExpected final result: 0x{:016x}", if a_val < b_val { 0xffffffffffffffff } else { 0 });
}