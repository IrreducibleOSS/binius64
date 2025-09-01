//! Debug BlackBox output directly

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;
use binius_beamish::expr::{Expr, ExprNode};

fn main() {
    let a_val = 5u64;
    let b_val = 10u64;
    println!("Testing BlackBox directly for {} < {}", a_val, b_val);
    
    // Create a BlackBox directly
    let a = val::<U64>(0);
    let b = val::<U64>(1);
    
    let blackbox_expr = Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("needs 2 inputs") };
            let not_a = !a;
            let (_, carry) = not_a.overflowing_add(*b);
            if carry { 0x8000_0000_0000_0000 } else { 0 }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }));
    
    let mut evaluator = ExpressionEvaluator::new(vec![a_val, b_val]);
    let blackbox_result = evaluator.evaluate(&blackbox_expr);
    println!("BlackBox result: 0x{:016x}", blackbox_result);
    
    // Now test sar on this value
    let sar_expr = sar(&blackbox_expr, 63);
    let mut evaluator2 = ExpressionEvaluator::new(vec![a_val, b_val]);
    let sar_result = evaluator2.evaluate(&sar_expr);
    println!("SAR result: 0x{:016x}", sar_result);
    
    // Test sar on a constant with MSB set
    let msb_const = constant::<U64>(0x8000_0000_0000_0000);
    let sar_const_expr = sar(&msb_const, 63);
    let mut evaluator3 = ExpressionEvaluator::new(vec![]);
    let sar_const_result = evaluator3.evaluate(&sar_const_expr);
    println!("SAR on constant 0x8000000000000000: 0x{:016x}", sar_const_result);
}