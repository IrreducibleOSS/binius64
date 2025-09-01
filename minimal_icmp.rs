//! Minimal icmp_ult without constraints

use binius_beamish::*;
use binius_beamish::types::U64;
use binius_beamish::compute::ExpressionEvaluator;

// Minimal icmp_ult that just does BlackBox + SAR
fn simple_icmp_ult(a: &Expr<U64>, b: &Expr<U64>) -> Expr<U64> {
    use binius_beamish::expr::ExprNode;
    
    // BlackBox computes the borrow chain for a < b
    let bout = Expr::wrap(std::rc::Rc::new(ExprNode::BlackBox {
        compute: |inputs| {
            let [a, b] = inputs else { panic!("icmp_ult needs 2 inputs") };
            // Compute borrow chain: ¬a + b, track if it carries out
            let not_a = !a;
            let (_, carry) = not_a.overflowing_add(*b);
            // If carry, set MSB; otherwise 0
            if carry { 0x8000_0000_0000_0000 } else { 0 }
        },
        inputs: vec![a.inner.clone(), b.inner.clone()],
    }));
    
    // Extract and broadcast MSB using built-in arithmetic right shift
    sar(&bout, 63)
}

fn main() {
    println!("Testing minimal icmp_ult (BlackBox + SAR only)");
    
    let test_cases = vec![
        (5u64, 10u64, true),   // 5 < 10 = true
        (10u64, 5u64, false),  // 10 < 5 = false
        (7u64, 7u64, false),   // 7 < 7 = false
    ];
    
    for (a_val, b_val, expected) in test_cases {
        println!("\nTesting {} < {} (expected: {})", a_val, b_val, expected);
        
        let a = val::<U64>(0);
        let b = val::<U64>(1);
        let result_expr = simple_icmp_ult(&a, &b);
        
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
}