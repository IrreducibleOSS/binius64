//! Demonstration of XOR folding optimization in Boojum
//!
//! This example shows how multiple XOR operations can be folded into 
//! single constraint operands, making them FREE in Binius64.
//!
//! Run with: cargo run --example boojum_xor_optimization_demo --release

use binius_core::Word;
use binius_frontend::boojum::{
    witness::WitnessContext,
    compiler::{ConstraintCompiler, OptimizationFlags},
};

fn main() {
    println!("=== XOR Folding Optimization Demo ===\n");
    
    // Create a computation with many XOR operations
    println!("Computing: (a ⊕ b ⊕ c ⊕ d ⊕ e) & mask = result\n");
    
    let mut ctx = WitnessContext::new();
    
    // Create field values
    let a = ctx.witness_field(Word(0x1111111111111111));
    let b = ctx.witness_field(Word(0x2222222222222222));
    let c = ctx.witness_field(Word(0x3333333333333333));
    let d = ctx.witness_field(Word(0x4444444444444444));
    let e = ctx.witness_field(Word(0x5555555555555555));
    let mask = ctx.witness_bits(Word(0xFF00FF00FF00FF00));
    
    // Chain of XOR operations
    let ab = ctx.field_add(a, b);
    let abc = ctx.field_add(ab, c);
    let abcd = ctx.field_add(abc, d);
    let abcde = ctx.field_add(abcd, e);
    
    // Convert to bits and apply mask
    let xor_result_bits = ctx.as_bits(abcde);
    let result = ctx.and(xor_result_bits, mask);
    
    println!("Witness computation complete:");
    println!("  Operations recorded: {}", ctx.operations().len());
    println!("  Result: 0x{:016X}\n", result.value.0);
    
    // Compile with NO optimization
    println!("─────────────────────────────────────");
    println!("NAIVE COMPILATION (no optimization):");
    println!("─────────────────────────────────────\n");
    
    let mut naive_compiler = ConstraintCompiler::new_naive();
    naive_compiler.compile(ctx.operations());
    
    let (naive_and, naive_mul) = naive_compiler.get_constraints();
    println!("Constraints generated:");
    println!("  AND constraints: {}", naive_and.len());
    println!("  MUL constraints: {}", naive_mul.len());
    println!("  Total cost: {:.1}", naive_and.len() as f64 + naive_mul.len() as f64 * 200.0);
    
    // Show the naive constraints
    println!("\nNaive constraint structure:");
    for (i, constraint) in naive_and.iter().enumerate() {
        println!("  Constraint #{}: operand_a[{}] & operand_b[{}] = operand_c[{}]",
                i, constraint.a.len(), constraint.b.len(), constraint.c.len());
    }
    
    // Compile with XOR optimization
    println!("\n─────────────────────────────────────");
    println!("OPTIMIZED COMPILATION (XOR folding):");
    println!("─────────────────────────────────────\n");
    
    let mut opt_compiler = ConstraintCompiler::new_with_options(OptimizationFlags::only_xor());
    opt_compiler.compile(ctx.operations());
    
    // Get optimization report before consuming compiler
    let opt_report = opt_compiler.optimization_report();
    
    let (opt_and, opt_mul) = opt_compiler.get_constraints();
    println!("Constraints generated:");
    println!("  AND constraints: {}", opt_and.len());
    println!("  MUL constraints: {}", opt_mul.len());
    println!("  Total cost: {:.1}", opt_and.len() as f64 + opt_mul.len() as f64 * 200.0);
    
    // Show the optimized constraints
    println!("\nOptimized constraint structure:");
    for (i, constraint) in opt_and.iter().enumerate() {
        println!("  Constraint #{}: operand_a[{}] & operand_b[{}] = operand_c[{}]",
                i, constraint.a.len(), constraint.b.len(), constraint.c.len());
        
        // Show when we have folded XORs
        if constraint.a.len() > 1 {
            println!("    → Operand A contains {} XORed values (FREE!)", constraint.a.len());
        }
    }
    
    // Print optimization report
    println!("\n{}", opt_report);
    
    // Calculate savings
    let constraints_saved = naive_and.len() - opt_and.len();
    let percentage_saved = if naive_and.len() > 0 {
        (constraints_saved * 100) / naive_and.len()
    } else {
        0
    };
    
    println!("\n=== SUMMARY ===");
    println!("Constraints eliminated: {} ({}% reduction)", constraints_saved, percentage_saved);
    println!("Key insight: XOR operations are FREE when folded into operands!");
    println!("\nIn the optimized version, (a ⊕ b ⊕ c ⊕ d ⊕ e) becomes a single");
    println!("operand with 5 components, requiring NO separate constraints!");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_xor_folding_saves_constraints() {
        let mut ctx = WitnessContext::new();
        
        // Create a chain of 10 XORs
        let mut values = Vec::new();
        for i in 0..10 {
            values.push(ctx.witness_field(Word(i as u64)));
        }
        
        let mut result = values[0];
        for i in 1..10 {
            result = ctx.field_add(result, values[i]);
        }
        
        // Compile both ways
        let mut naive = ConstraintCompiler::new_naive();
        naive.compile(ctx.operations());
        let (naive_constraints, _) = naive.get_constraints();
        
        let mut optimized = ConstraintCompiler::new_with_options(OptimizationFlags::only_xor());
        optimized.compile(ctx.operations());
        let (opt_constraints, _) = optimized.get_constraints();
        
        // Optimized should have significantly fewer constraints
        assert!(opt_constraints.len() < naive_constraints.len());
        
        // Specifically, we should save ~9 constraints (one for each intermediate XOR)
        let saved = naive_constraints.len() - opt_constraints.len();
        assert!(saved >= 8, "Should save at least 8 constraints, saved {}", saved);
    }
}