//! Demonstration of precise type semantics in Boojum
//!
//! This example shows how the same Word value has different interpretations
//! in different operations, and how we track these interpretations precisely.
//!
//! Run with: cargo run --example boojum_type_demo --release

use binius_core::Word;
use binius_frontend::boojum::{
    witness::WitnessContext,
    compiler::ConstraintCompiler,
};

fn main() {
    println!("=== Boojum Type Semantics Demonstration ===\n");
    
    // Create the same bit pattern
    let pattern = Word(0xF0F0F0F0F0F0F0F0);
    println!("Starting with Word(0x{:016X})\n", pattern.0);
    
    println!("This same value has THREE different interpretations:");
    println!("1. As binary field element: for polynomial operations");
    println!("2. As unsigned integer: {} in decimal", pattern.0);
    println!("3. As bit pattern: for masking operations\n");
    
    demonstrate_field_semantics();
    demonstrate_integer_semantics();
    demonstrate_bit_pattern_semantics();
    demonstrate_type_transitions();
}

fn demonstrate_field_semantics() {
    println!("=== Field Element Semantics (GF(2^64)) ===\n");
    
    let mut ctx = WitnessContext::new();
    
    // In GF(2^64), addition is XOR
    let a = ctx.witness(Word(0x3));
    let b = ctx.witness(Word(0x5));
    let field_sum = ctx.bxor(a, b);
    
    println!("Field addition (XOR):");
    println!("  0x3 ⊕ 0x5 = 0x{:X} (field element)", field_sum.value.0);
    println!("  Note: This is 6, NOT 8!");
    println!("  In GF(2^64): addition is XOR\n");
    
    // Field elements can be accumulated with XOR
    let c = ctx.witness(Word(0x9));
    let field_total = ctx.bxor(field_sum, c);
    println!("Accumulation: 0x6 ⊕ 0x9 = 0x{:X}", field_total.value.0);
    
    // Compile to show XOR is FREE
    let mut compiler = ConstraintCompiler::new();
    compiler.compile(ctx.operations());
    let (and_constraints, _) = compiler.get_constraints();
    
    println!("Constraints for field operations: {} AND constraints", and_constraints.len());
    println!("  (XOR is FREE in operands!)\n");
}

fn demonstrate_integer_semantics() {
    println!("=== Unsigned Integer Semantics (mod 2^64) ===\n");
    
    let mut ctx = WitnessContext::new();
    
    // In unsigned integer arithmetic, addition has carry
    let a = ctx.witness(Word(0xFFFFFFFFFFFFFFFF)); // MAX_U64
    let b = ctx.witness(Word(1));
    let zero = ctx.constant(Word::ZERO);
    
    let (int_sum, carry) = ctx.add_with_carry(a, b, zero);
    
    println!("Unsigned integer addition:");
    println!("  0x{:016X} + 1 = 0x{:016X}", a.value.0, int_sum.value.0);
    println!("  Carry out: 0x{:X}", carry.value.0);
    println!("  Note: MAX_U64 + 1 wraps to 0 with carry!\n");
    
    // Multi-limb arithmetic
    println!("128-bit addition (two 64-bit limbs):");
    let a_low = ctx.witness(Word(0xFFFFFFFFFFFFFFFF));
    let a_high = ctx.witness(Word(0));
    let b_low = ctx.witness(Word(1));
    let b_high = ctx.witness(Word(0));
    
    let (sum_low, carry_low) = ctx.add_with_carry(a_low, b_low, zero);
    let (sum_high, _) = ctx.add_with_carry(a_high, b_high, carry_low);
    
    println!("  [0x{:016X}, 0x{:016X}]", a_low.value.0, a_high.value.0);
    println!("  + [0x{:016X}, 0x{:016X}]", b_low.value.0, b_high.value.0);
    println!("  = [0x{:016X}, 0x{:016X}]", sum_low.value.0, sum_high.value.0);
    println!("  This represents 2^64 in 128-bit arithmetic\n");
    
    // Compile to show carry constraints
    let mut compiler = ConstraintCompiler::new();
    compiler.compile(ctx.operations());
    let (and_constraints, _) = compiler.get_constraints();
    
    println!("Constraints for integer operations: {} AND constraints", and_constraints.len());
    println!("  (Carry propagation needs AND constraints)\n");
}

fn demonstrate_bit_pattern_semantics() {
    println!("=== Bit Pattern Semantics (no arithmetic) ===\n");
    
    let mut ctx = WitnessContext::new();
    
    // Bitwise operations treat Word as bit patterns
    let a = ctx.witness(Word(0xFF00FF00FF00FF00));
    let b = ctx.witness(Word(0x00FF00FF00FF00FF));
    let and_result = ctx.band(a, b);
    
    println!("Bitwise AND:");
    println!("  0x{:016X}", a.value.0);
    println!("  & 0x{:016X}", b.value.0);
    println!("  = 0x{:016X}\n", and_result.value.0);
    
    // Shifts are FREE - they become ShiftedValueIndex
    let shifted_left = ctx.shl(a, 8);
    let shifted_right = ctx.shr(b, 4);
    
    println!("Logical shifts (FREE in constraints):");
    println!("  0x{:016X} << 8 = 0x{:016X}", a.value.0, shifted_left.value.0);
    println!("  0x{:016X} >> 4 = 0x{:016X}\n", b.value.0, shifted_right.value.0);
    
    // Arithmetic shift for sign extension
    let signed_val = ctx.witness(Word(0x8000000000000000)); // Negative in signed
    let sar_result = ctx.sar(signed_val, 1);
    
    println!("Arithmetic right shift (sign extension):");
    println!("  0x{:016X} >>> 1 = 0x{:016X}", signed_val.value.0, sar_result.value.0);
    println!("  Note: MSB (sign bit) is replicated\n");
    
    // Boolean masking pattern
    let bool_true = ctx.witness(Word::ALL_ONE); // -1 as signed
    let mask = ctx.sar(bool_true, 63); // Spread sign bit
    let value = ctx.witness(Word(0x123456789ABCDEF0));
    let selected = ctx.band(value, mask);
    
    println!("Boolean selection pattern:");
    println!("  bool = {} (0x{:016X})", 
            if bool_true.value == Word::ALL_ONE { "true" } else { "false" },
            bool_true.value.0);
    println!("  mask = SAR(bool, 63) = 0x{:016X}", mask.value.0);
    println!("  value & mask = 0x{:016X} (selected)\n", selected.value.0);
}

fn demonstrate_type_transitions() {
    println!("=== Type Transitions in Complex Operations ===\n");
    
    let mut ctx = WitnessContext::new();
    
    // Conditional accumulation: combines all three interpretations
    let values = vec![
        ctx.witness(Word(10)),
        ctx.witness(Word(20)),
        ctx.witness(Word(30)),
    ];
    
    let selections = vec![
        ctx.witness(Word::ALL_ONE),  // true
        ctx.witness(Word::ZERO),      // false
        ctx.witness(Word::ALL_ONE),  // true
    ];
    
    println!("Conditional accumulation (10 + 30, skipping 20):\n");
    
    let mut sum = ctx.constant(Word::ZERO);
    let zero = ctx.constant(Word::ZERO);
    
    for i in 0..3 {
        println!("Step {}:", i + 1);
        
        // Type: signed int -> bit pattern
        let mask = ctx.sar(selections[i], 63);
        println!("  selection[{}] = {} -> mask = 0x{:016X}", 
                i, 
                if selections[i].value == Word::ALL_ONE { "true" } else { "false" },
                mask.value.0);
        
        // Type: bit pattern -> bit pattern
        let masked = ctx.band(values[i], mask);
        println!("  values[{}] & mask = {} (bit pattern)", i, masked.value.0);
        
        // Type: bit pattern -> unsigned int (context change!)
        let (new_sum, _) = ctx.add_with_carry(sum, masked, zero);
        println!("  sum + masked = {} (unsigned int)\n", new_sum.value.0);
        
        sum = new_sum;
    }
    
    println!("Final sum: {} (should be 10 + 30 = 40)\n", sum.value.0);
    
    // Show constraint generation
    let mut compiler = ConstraintCompiler::new();
    compiler.compile(ctx.operations());
    let (and_constraints, mul_constraints) = compiler.get_constraints();
    
    println!("=== Constraint Summary ===");
    println!("Total AND constraints: {}", and_constraints.len());
    println!("Total MUL constraints: {}", mul_constraints.len());
    println!("\nKey insights:");
    println!("- Same Word values interpreted differently in each operation");
    println!("- Type interpretation determines constraint generation");
    println!("- Shifts and XORs are FREE (encoded in operands)");
    println!("- AND and carry operations need explicit constraints");
}