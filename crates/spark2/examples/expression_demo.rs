//! Demo of expression building and rewriting

use binius_spark2::{
    Expr,
    core::rewrite::Rewriter,
};

fn main() {
    println!("=== Expression Building Demo ===\n");
    
    // XOR chain example
    println!("XOR Chain (FREE in Binius64):");
    let xor_chain = Expr::val(0)
        .xor(Expr::val(1))
        .xor(Expr::val(2))
        .xor(Expr::val(3))
        .xor(Expr::val(4));
    println!("  Expression: {}", xor_chain);
    println!("  Constraints needed: 0 (single operand!)\n");
    
    // SHA256 Sigma example
    println!("SHA256 Sigma0 (rotation XOR):");
    let sigma0 = Expr::val(0).ror(2)
        .xor(Expr::val(0).ror(13))
        .xor(Expr::val(0).ror(22));
    println!("  Expression: {}", sigma0);
    println!("  Constraints needed: 0 (single operand!)\n");
    
    // Keccak chi pattern
    println!("Keccak Chi Pattern:");
    let chi = Expr::val(0).xor(
        Expr::val(1).not().and(Expr::val(2))
    );
    println!("  Expression: {}", chi);
    println!("  Naive constraints: 3");
    println!("  Optimized constraints: 1\n");
    
    // Conditional (multiplexer)
    println!("Multiplexer:");
    let mux = Expr::cond(
        Expr::val(0),
        Expr::val(1),
        Expr::val(2)
    );
    println!("  Expression: {}", mux);
    println!("  Constraints needed: 2\n");
    
    // Rewriting demo
    println!("=== Rewriting Demo ===\n");
    
    let rewriter = Rewriter::with_standard_rules();
    
    // XOR with self
    let expr1 = Expr::val(0).xor(Expr::val(0));
    println!("XOR with self:");
    println!("  Original: {}", expr1);
    let rewritten1 = rewriter.rewrite(&expr1);
    println!("  Rewritten: {}\n", rewritten1);
    
    // XOR with zero
    let expr2 = Expr::val(0).xor(Expr::constant(0));
    println!("XOR with zero:");
    println!("  Original: {}", expr2);
    let rewritten2 = rewriter.rewrite(&expr2);
    println!("  Rewritten: {}\n", rewritten2);
    
    // Double NOT
    let expr3 = Expr::val(0).not().not();
    println!("Double NOT:");
    println!("  Original: {}", expr3);
    let rewritten3 = rewriter.rewrite(&expr3);
    println!("  Rewritten: {}\n", rewritten3);
    
    // AND with zero
    let expr4 = Expr::val(0).and(Expr::constant(0));
    println!("AND with zero:");
    println!("  Original: {}", expr4);
    let rewritten4 = rewriter.rewrite(&expr4);
    println!("  Rewritten: {}\n", rewritten4);
}