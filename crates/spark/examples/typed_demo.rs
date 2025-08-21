//! Demonstration of the new typed Spark system
//!
//! Run with: cargo run --example typed_demo --release

use binius_core::Word;
use binius_spark::{
    witness::{WitnessContext},
    compiler::ConstraintCompiler,
    constraints::ConstraintOptimizer,
};

fn main() {
    println!("=== Spark Typed System Demonstration ===\n");
    
    // Create witness context
    let mut ctx = WitnessContext::new();
    
    // Field operations (GF(2^64))
    println!("1. Field Operations (GF(2^64)):");
    let a = ctx.witness_field(Word(3));
    let b = ctx.witness_field(Word(5));
    let field_sum = ctx.add(a, b);  // XOR = field addition
    println!("   0x3 ⊕ 0x5 = 0x{:X} (field addition)", field_sum.value.0);
    
    // Alternative syntax using alias
    let c = ctx.witness_field(Word(7));
    let field_total = ctx.xor(field_sum, c);  // Same as field_add
    println!("   0x6 ⊕ 0x7 = 0x{:X} (using xor alias)", field_total.value.0);
    
    // Integer operations (mod 2^64)
    println!("\n2. Unsigned Integer Operations:");
    let x = ctx.witness_uint(Word(100));
    let y = ctx.witness_uint(Word(200));
    let zero = ctx.zero_uint();
    let (int_sum, carry) = ctx.add_with_carry(x, y, zero);
    println!("   100 + 200 = {} (carry: {})", int_sum.value.0, carry.value.0);
    
    // Alternative syntax using alias  
    let z = ctx.witness_uint(Word(50));
    let (total, _carry2) = ctx.adc(int_sum, z, zero);
    println!("   {} + 50 = {} (using adc alias)", int_sum.value.0, total.value.0);
    
    // Bit operations
    println!("\n3. Bit Pattern Operations:");
    let mask = ctx.witness_bits(Word(0xFF00FF00FF00FF00));
    let value = ctx.witness_bits(Word(0x123456789ABCDEF0));
    let masked = ctx.and(mask, value);
    println!("   0x{:016X} & 0x{:016X} = 0x{:016X}", 
             mask.value.0, value.value.0, masked.value.0);
    
    // Shifts (demonstrating they're free)
    let shifted = ctx.shl(value, 8);
    println!("   0x{:016X} << 8 = 0x{:016X} (shift is FREE!)", 
             value.value.0, shifted.value.0);
    
    // Type conversions
    println!("\n4. Type Conversions (zero-cost):");
    let bits_val = ctx.witness_bits(Word(42));
    let as_field = ctx.as_field(bits_val);
    let as_uint = ctx.as_uint(bits_val);
    println!("   Same Word(42) used as:");
    println!("     Bits: 0x{:016X}", bits_val.value.0);
    println!("     Field: 0x{:016X}", as_field.value.0);
    println!("     UInt: {}", as_uint.value.0);
    
    // Compilation to constraints
    println!("\n=== Constraint Compilation ===");
    
    let mut compiler = ConstraintCompiler::new();
    compiler.compile(ctx.operations());
    
    let (and_constraints, mul_constraints) = compiler.get_constraints();
    
    println!("Generated constraints:");
    println!("  AND constraints: {}", and_constraints.len());
    println!("  MUL constraints: {}", mul_constraints.len());
    
    // Pattern analysis
    println!("\n=== Pattern Analysis ===");
    let mut optimizer = ConstraintOptimizer::new();
    optimizer.analyze(ctx.operations());
    
    let stats = optimizer.stats();
    println!("{}", stats);
    
    println!("\n=== Key Benefits ===");
    println!("✓ Compile-time type safety - cannot mix field/int operations");
    println!("✓ 1-1 method-to-operation mapping - perfect traceability");
    println!("✓ Clear semantics - type determines constraint generation");
    println!("✓ Zero runtime cost - all type checking at compile time");
    println!("✓ Explicit conversions - no hidden type coercion");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_typed_safety() {
        let mut ctx = WitnessContext::new();
        
        // This works - field operations
        let a = ctx.witness_field(Word(3));
        let b = ctx.witness_field(Word(5));
        let _sum = ctx.add(a, b);
        
        // This works - uint operations
        let x = ctx.witness_uint(Word(10));
        let y = ctx.witness_uint(Word(20));
        let z = ctx.zero_uint();
        let (_sum2, _carry) = ctx.add_with_carry(x, y, z);
        
        // This works - bit operations
        let bits1 = ctx.witness_bits(Word(0xFF));
        let bits2 = ctx.witness_bits(Word(0x0F));
        let _masked = ctx.and(bits1, bits2);
        
        // Compile-time type safety prevents mixing:
        // let wrong = ctx.add(a, x);  // Would not compile!
        // let wrong2 = ctx.add_with_carry(a, b, z); // Would not compile!
        
        assert!(true, "Type safety ensured at compile time");
    }
}