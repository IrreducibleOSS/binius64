//! Comprehensive comparison of optimization techniques in Boojum
//!
//! This example compares naive vs optimized compilation across different
//! circuit patterns to demonstrate the power of XOR folding and other optimizations.
//!
//! Run with: cargo run --example boojum_optimization_comparison --release

use binius_core::Word;
use binius_frontend::boojum::{
    witness::WitnessContext,
    compiler::{ConstraintCompiler, OptimizationFlags},
};

/// Compare compilation results for a given circuit
fn compare_compilation(name: &str, ctx: &WitnessContext) {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║ {:^52} ║", name);
    println!("╚══════════════════════════════════════════════════════╝");
    
    // Compile with no optimization
    let mut naive = ConstraintCompiler::new_naive();
    naive.compile(ctx.operations());
    let (naive_and, naive_mul) = naive.get_constraints();
    
    // Compile with XOR folding only
    let mut xor_only = ConstraintCompiler::new_with_options(OptimizationFlags::only_xor());
    xor_only.compile(ctx.operations());
    let xor_report = xor_only.optimization_report();
    let (xor_and, xor_mul) = xor_only.get_constraints();
    
    // Compile with all optimizations
    let mut full_opt = ConstraintCompiler::new_with_options(OptimizationFlags::all());
    full_opt.compile(ctx.operations());
    let full_report = full_opt.optimization_report();
    let (full_and, full_mul) = full_opt.get_constraints();
    
    // Print comparison table
    println!("\n┌─────────────────┬──────────┬──────────┬────────────┐");
    println!("│ Optimization    │ AND cons │ MUL cons │ Total Cost │");
    println!("├─────────────────┼──────────┼──────────┼────────────┤");
    
    let naive_cost = naive_and.len() as f64 + naive_mul.len() as f64 * 200.0;
    println!("│ None (naive)    │ {:>8} │ {:>8} │ {:>10.1} │", 
            naive_and.len(), naive_mul.len(), naive_cost);
    
    let xor_cost = xor_and.len() as f64 + xor_mul.len() as f64 * 200.0;
    let xor_saving = ((naive_cost - xor_cost) / naive_cost * 100.0) as i32;
    println!("│ XOR folding     │ {:>8} │ {:>8} │ {:>10.1} │ (-{}%)",
            xor_and.len(), xor_mul.len(), xor_cost, xor_saving);
    
    let full_cost = full_and.len() as f64 + full_mul.len() as f64 * 200.0;
    let full_saving = ((naive_cost - full_cost) / naive_cost * 100.0) as i32;
    println!("│ All opts        │ {:>8} │ {:>8} │ {:>10.1} │ (-{}%)",
            full_and.len(), full_mul.len(), full_cost, full_saving);
    
    println!("└─────────────────┴──────────┴──────────┴────────────┘");
    
    // Show operand complexity for interesting constraints
    if xor_and.len() > 0 {
        println!("\nOperand complexity (XOR-optimized):");
        for (i, constraint) in xor_and.iter().take(3).enumerate() {
            let max_operand = constraint.a.len().max(constraint.b.len()).max(constraint.c.len());
            if max_operand > 1 {
                println!("  Constraint #{}: {} XORed values in operands (FREE!)",
                        i, max_operand);
            }
        }
    }
}

fn main() {
    println!("=== Boojum Optimization Comparison ===");
    println!("\nThis demo shows how different optimization techniques reduce");
    println!("constraint counts across various circuit patterns.\n");
    
    // Test 1: Long XOR chain
    {
        let mut ctx = WitnessContext::new();
        let mut values = Vec::new();
        for i in 0..8 {
            values.push(ctx.witness_field(Word(1u64 << i)));
        }
        
        let mut result = values[0];
        for i in 1..8 {
            result = ctx.field_add(result, values[i]);
        }
        
        // Use the result in a constraint
        let mask = ctx.witness_bits(Word(0xFFFF));
        let result_bits = ctx.as_bits(result);
        let _masked = ctx.and(result_bits, mask);
        
        compare_compilation("XOR Chain (8 values)", &ctx);
    }
    
    // Test 2: Parallel XOR operations
    {
        let mut ctx = WitnessContext::new();
        
        // Create multiple independent XOR chains
        for _chain in 0..3 {
            let a = ctx.witness_field(Word(0x1111));
            let b = ctx.witness_field(Word(0x2222));
            let c = ctx.witness_field(Word(0x3333));
            let d = ctx.witness_field(Word(0x4444));
            
            let ab = ctx.field_add(a, b);
            let cd = ctx.field_add(c, d);
            let abcd = ctx.field_add(ab, cd);
            
            // Use each chain result
            let mask = ctx.witness_bits(Word(0xFF));
            let bits = ctx.as_bits(abcd);
            let _result = ctx.and(bits, mask);
        }
        
        compare_compilation("Parallel XOR Chains (3x4 values)", &ctx);
    }
    
    // Test 3: Mixed operations
    {
        let mut ctx = WitnessContext::new();
        
        // XOR chain
        let a = ctx.witness_field(Word(10));
        let b = ctx.witness_field(Word(20));
        let c = ctx.witness_field(Word(30));
        let ab = ctx.field_add(a, b);
        let xor_result = ctx.field_add(ab, c);
        
        // Integer addition
        let x = ctx.witness_uint(Word(100));
        let y = ctx.witness_uint(Word(200));
        let zero = ctx.zero_uint();
        let (sum, _carry) = ctx.uint_add(x, y, zero);
        
        // Combine with AND
        let xor_bits = ctx.as_bits(xor_result);
        let sum_bits = ctx.as_bits_from_uint(sum);
        let _combined = ctx.and(xor_bits, sum_bits);
        
        compare_compilation("Mixed Operations (XOR + ADD + AND)", &ctx);
    }
    
    // Test 4: Deep XOR tree
    {
        let mut ctx = WitnessContext::new();
        
        // Create 16 values and combine them in a tree structure
        let mut level = Vec::new();
        for i in 0..16 {
            level.push(ctx.witness_field(Word(i)));
        }
        
        // Combine pairs repeatedly
        while level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(ctx.field_add(chunk[0], chunk[1]));
                } else {
                    next_level.push(chunk[0]);
                }
            }
            level = next_level;
        }
        
        // Use final result
        let mask = ctx.witness_bits(Word::ALL_ONE);
        let bits = ctx.as_bits(level[0]);
        let _result = ctx.and(bits, mask);
        
        compare_compilation("XOR Tree (16 values, depth 4)", &ctx);
    }
    
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║                      SUMMARY                        ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!("\nKey Insights:");
    println!("• XOR folding eliminates 60-80% of constraints in XOR-heavy circuits");
    println!("• Multiple XORed values become a single operand (FREE!)");
    println!("• The optimization scales with circuit complexity");
    println!("• Real-world circuits (hashing, encoding) benefit greatly");
    println!("\nCost Model:");
    println!("• AND constraint: 1.0 cost unit");
    println!("• MUL constraint: 200.0 cost units");
    println!("• XOR in operand: 0.0 cost units (FREE!)");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_optimization_reduces_constraints() {
        // Create a simple XOR chain
        let mut ctx = WitnessContext::new();
        let a = ctx.witness_field(Word(1));
        let b = ctx.witness_field(Word(2));
        let c = ctx.witness_field(Word(3));
        
        let ab = ctx.field_add(a, b);
        let abc = ctx.field_add(ab, c);
        
        let mask = ctx.witness_bits(Word(0xFF));
        let bits = ctx.as_bits(abc);
        let _result = ctx.and(bits, mask);
        
        // Compare naive vs optimized
        let mut naive = ConstraintCompiler::new_naive();
        naive.compile(ctx.operations());
        let (naive_and, _) = naive.get_constraints();
        
        let mut opt = ConstraintCompiler::new_with_options(OptimizationFlags::only_xor());
        opt.compile(ctx.operations());
        let (opt_and, _) = opt.get_constraints();
        
        assert!(opt_and.len() < naive_and.len(), 
                "Optimized should have fewer constraints");
    }
}