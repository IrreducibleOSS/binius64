//! Demonstration that Boojum uses the EXACT backend constraint types
//!
//! Run with: cargo run --example boojum_demo --release

use binius_core::{
    constraint_system::{AndConstraint, MulConstraint, ShiftedValueIndex},
    word::Word,
};
use binius_frontend::boojum::{
    witness::WitnessContext,
    compiler::ConstraintCompiler,
};

fn main() {
    println!("=== Boojum Direct Constraint Generation Demo ===\n");
    
    // Create a simple computation
    let mut ctx = WitnessContext::new();
    
    // Some witness values
    let a = ctx.witness(Word(0xFF00FF00FF00FF00));
    let b = ctx.witness(Word(0x00FF00FF00FF00FF));
    
    println!("Witness computation:");
    println!("  a = 0x{:016X}", a.value.0);
    println!("  b = 0x{:016X}", b.value.0);
    
    // Perform operations
    let c = ctx.band(a, b);
    println!("  c = a & b = 0x{:016X}", c.value.0);
    
    let d = ctx.shl(c, 8);
    println!("  d = c << 8 = 0x{:016X}", d.value.0);
    
    let e = ctx.sar(a, 4);
    println!("  e = a >> 4 (arithmetic) = 0x{:016X}", e.value.0);
    
    let f = ctx.bxor(d, e);
    println!("  f = d ^ e = 0x{:016X}", f.value.0);
    
    // Now compile DIRECTLY to backend constraint types
    println!("\n=== Direct Compilation to Backend Types ===\n");
    
    let mut compiler = ConstraintCompiler::new();
    compiler.compile(ctx.operations());
    
    let (and_constraints, mul_constraints) = compiler.get_constraints();
    
    // These are ACTUAL binius_core::constraint_system types!
    println!("Generated constraints:");
    println!("  Type: binius_core::constraint_system::AndConstraint");
    println!("  Count: {}", and_constraints.len());
    println!("  Type: binius_core::constraint_system::MulConstraint");
    println!("  Count: {}", mul_constraints.len());
    
    // Show the structure
    if let Some(first) = and_constraints.first() {
        println!("\nFirst AND constraint structure:");
        println!("  a operand: {} shifted values", first.a.len());
        println!("  b operand: {} shifted values", first.b.len());
        println!("  c operand: {} shifted values", first.c.len());
        
        // Show shifted value details
        if let Some(term) = first.a.first() {
            println!("\n  Example operand term:");
            println!("    Value index: {}", term.value_index.0);
            println!("    Shift type: {:?}", term.shift_variant);
            println!("    Shift amount: {}", term.amount);
        }
    }
    
    println!("\n=== Key Points ===");
    println!("1. We use the EXACT types from binius_core::constraint_system");
    println!("2. Shifts (shl, sar) generate NO constraints - they're FREE in operands");
    println!("3. Each operation maps directly to AND/MUL constraints");
    println!("4. Type safety ensures we can ONLY generate valid Binius64 constraints");
}