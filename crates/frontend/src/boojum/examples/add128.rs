//! 128-bit addition in the Boojum paradigm
//!
//! This example shows how to implement 128-bit unsigned integer addition
//! using two 64-bit limbs with carry propagation.

use binius_core::Word;
use crate::boojum::{TrackedWord, witness::WitnessContext, compiler::ConstraintCompiler, UIntValue};

/// Input for 128-bit addition
pub struct Add128Input {
    /// First number as [low, high] limbs
    pub a: [Word; 2],
    /// Second number as [low, high] limbs  
    pub b: [Word; 2],
}

/// Output of 128-bit addition
pub struct Add128Output {
    /// Sum as [low, high] limbs
    pub sum: [Word; 2],
    /// Whether overflow occurred
    pub overflow: bool,
}

/// 128-bit addition in Boojum paradigm
pub struct Add128Boojum;

impl Add128Boojum {
    /// Pure witness computation - just adds two 128-bit numbers
    pub fn compute_witness_pure(input: &Add128Input) -> Add128Output {
        // Add low limbs
        let low_sum = input.a[0].0.wrapping_add(input.b[0].0);
        let low_carry = if low_sum < input.a[0].0 { 1 } else { 0 };
        
        // Add high limbs with carry
        let high_sum = input.a[1].0.wrapping_add(input.b[1].0).wrapping_add(low_carry);
        let high_carry = if high_sum < input.a[1].0 || 
                           (low_carry == 1 && high_sum == input.a[1].0) { 
            true 
        } else { 
            false 
        };
        
        Add128Output {
            sum: [Word(low_sum), Word(high_sum)],
            overflow: high_carry,
        }
    }
    
    /// Tracked witness computation with carry propagation
    pub fn compute_witness_tracked(
        ctx: &mut WitnessContext,
        input: &Add128Input,
    ) -> Add128Output {
        // Create tracked values for inputs as unsigned integers
        let a_low = ctx.witness_uint(input.a[0]);
        let a_high = ctx.witness_uint(input.a[1]);
        let b_low = ctx.witness_uint(input.b[0]);
        let b_high = ctx.witness_uint(input.b[1]);
        
        // Add low limbs with carry out
        let zero = ctx.zero_uint();
        let (sum_low, carry_low) = ctx.uint_add(a_low, b_low, zero);
        
        // Add high limbs with carry in
        let (sum_high, carry_high) = ctx.uint_add(a_high, b_high, carry_low);
        
        // Check for overflow (carry_high MSB should be 0 for no overflow)
        let carry_bits = ctx.as_bits_from_uint(carry_high);
        let carry_msb = ctx.shr(carry_bits, 63);
        let overflow = carry_msb.value.0 != 0;
        
        // If we want to enforce no overflow, we'd assert:
        // ctx.assert_zero_bits(carry_msb, "no overflow in 128-bit addition");
        
        Add128Output {
            sum: [sum_low.value, sum_high.value],
            overflow,
        }
    }
    
    /// Version that asserts no overflow
    pub fn compute_witness_tracked_no_overflow(
        ctx: &mut WitnessContext,
        input: &Add128Input,
    ) -> [UIntValue; 2] {
        // Create tracked values for inputs as unsigned integers
        let a_low = ctx.witness_uint(input.a[0]);
        let a_high = ctx.witness_uint(input.a[1]);
        let b_low = ctx.witness_uint(input.b[0]);
        let b_high = ctx.witness_uint(input.b[1]);
        
        // Add low limbs with carry out
        let zero = ctx.zero_uint();
        let (sum_low, carry_low) = ctx.uint_add(a_low, b_low, zero);
        
        // Add high limbs with carry in
        let (sum_high, carry_high) = ctx.uint_add(a_high, b_high, carry_low);
        
        // Assert no overflow
        let carry_bits = ctx.as_bits_from_uint(carry_high);
        let carry_msb = ctx.shr(carry_bits, 63);
        ctx.assert_zero_bits(carry_msb, "no overflow in 128-bit addition");
        
        [sum_low, sum_high]
    }
}

/// Example: 256-bit addition using the 128-bit building block
pub struct Add256Boojum;

impl Add256Boojum {
    /// Add two 256-bit numbers represented as 4 limbs each
    pub fn compute_witness_tracked(
        ctx: &mut WitnessContext,
        a: [Word; 4],
        b: [Word; 4],
    ) -> [UIntValue; 4] {
        let zero = ctx.zero_uint();
        let mut sum = Vec::with_capacity(4);
        let mut carry = zero;
        
        // Add limb by limb with carry propagation
        for i in 0..4 {
            let a_limb = ctx.witness_uint(a[i]);
            let b_limb = ctx.witness_uint(b[i]);
            let (sum_limb, carry_out) = ctx.uint_add(a_limb, b_limb, carry);
            sum.push(sum_limb);
            carry = carry_out;
        }
        
        // Assert final carry is zero (no overflow)
        let final_carry_bits = ctx.as_bits_from_uint(carry);
        let final_carry_msb = ctx.shr(final_carry_bits, 63);
        ctx.assert_zero_bits(final_carry_msb, "no overflow in 256-bit addition");
        
        [sum[0], sum[1], sum[2], sum[3]]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_128bit_addition_simple() {
        // Test: 100 + 200 = 300
        let input = Add128Input {
            a: [Word(100), Word(0)],
            b: [Word(200), Word(0)],
        };
        
        let output = Add128Boojum::compute_witness_pure(&input);
        assert_eq!(output.sum[0], Word(300));
        assert_eq!(output.sum[1], Word(0));
        assert!(!output.overflow);
    }
    
    #[test]
    fn test_128bit_addition_with_carry() {
        // Test: (2^64 - 1) + 1 = 2^64 (carry to high limb)
        let input = Add128Input {
            a: [Word(u64::MAX), Word(0)],
            b: [Word(1), Word(0)],
        };
        
        let output = Add128Boojum::compute_witness_pure(&input);
        assert_eq!(output.sum[0], Word(0));
        assert_eq!(output.sum[1], Word(1));
        assert!(!output.overflow);
        
        // Test tracked version
        let mut ctx = WitnessContext::new();
        let tracked_output = Add128Boojum::compute_witness_tracked(&mut ctx, &input);
        assert_eq!(tracked_output.sum[0], Word(0));
        assert_eq!(tracked_output.sum[1], Word(1));
    }
    
    #[test]
    fn test_128bit_addition_max_values() {
        // Test: (2^64 - 1, 2^64 - 1) + (0, 1) = (2^64 - 1, 2^64) with carry
        let input = Add128Input {
            a: [Word(u64::MAX), Word(u64::MAX - 1)],
            b: [Word(0), Word(1)],
        };
        
        let output = Add128Boojum::compute_witness_pure(&input);
        assert_eq!(output.sum[0], Word(u64::MAX));
        assert_eq!(output.sum[1], Word(u64::MAX));
        assert!(!output.overflow);
    }
    
    #[test]
    fn test_256bit_addition() {
        // Simple 256-bit addition
        let a = [Word(100), Word(200), Word(300), Word(400)];
        let b = [Word(1), Word(2), Word(3), Word(4)];
        
        let mut ctx = WitnessContext::new();
        let sum = Add256Boojum::compute_witness_tracked(&mut ctx, a, b);
        
        assert_eq!(sum[0].value, Word(101));
        assert_eq!(sum[1].value, Word(202));
        assert_eq!(sum[2].value, Word(303));
        assert_eq!(sum[3].value, Word(404));
        
        // Verify operations were recorded
        assert!(!ctx.operations().is_empty());
    }
    
    #[test]
    fn test_constraint_generation() {
        let input = Add128Input {
            a: [Word(100), Word(200)],
            b: [Word(300), Word(400)],
        };
        
        let mut ctx = WitnessContext::new();
        let _ = Add128Boojum::compute_witness_tracked_no_overflow(&mut ctx, &input);
        
        // Compile to constraints
        let mut compiler = ConstraintCompiler::new();
        compiler.compile(ctx.operations());
        let (and_constraints, mul_constraints) = compiler.get_constraints();
        
        // Should generate AND constraints for carry propagation
        assert!(!and_constraints.is_empty());
        println!("128-bit addition generated {} AND constraints", and_constraints.len());
        assert_eq!(mul_constraints.len(), 0, "Addition should not use MUL constraints");
    }
}