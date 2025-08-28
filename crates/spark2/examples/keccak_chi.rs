//! Example demonstrating Keccak chi optimization

use binius_spark2::{
    gadgets::keccak::KeccakChi,
    core::rewrite::Rewriter,
    patterns::crypto::add_crypto_rules,
};

fn main() {
    println!("=== Keccak Chi Optimization Demo ===\n");
    
    // Create chi gadget
    let chi = KeccakChi::new(0, 5);
    
    // Build expressions
    let expressions = chi.build_expressions();
    
    println!("Chi expressions:");
    for (i, expr) in expressions.iter().enumerate() {
        println!("  chi[{}] = {}", i, expr);
    }
    println!();
    
    // Show constraint counts
    println!("Constraint analysis:");
    println!("  Naive implementation: {} AND constraints", chi.count_naive_constraints());
    println!("  Optimized (rewritten): {} AND constraints", chi.count_optimized_constraints());
    println!("  Reduction factor: {}x", chi.count_naive_constraints() / chi.count_optimized_constraints());
    println!();
    
    // Show optimized constraints
    println!("Optimized constraints:");
    for i in 0..5 {
        println!("  [{}] {}", i, chi.generate_optimized_constraint(i));
    }
    println!();
    
    // Demonstrate rewriting
    let mut rewriter = Rewriter::with_standard_rules();
    add_crypto_rules(&mut rewriter);
    
    println!("Expression rewriting demo:");
    let test_expr = expressions[0].clone();
    println!("  Original: {}", test_expr);
    let rewritten = rewriter.rewrite(&test_expr);
    println!("  Rewritten: {}", rewritten);
}