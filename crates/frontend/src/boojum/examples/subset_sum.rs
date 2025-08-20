//! Subset Sum implemented with the Boojum paradigm
//!
//! This demonstrates the separation of witness computation from constraint generation.
//! The same problem as circuits/subset_sum.rs but with our new architecture.

use binius_core::Word;
use crate::boojum::{witness::WitnessContext, compiler::ConstraintCompiler};

/// Subset sum problem in the Boojum paradigm
pub struct SubsetSumBoojum;

/// Input to the subset sum problem
pub struct SubsetSumInput {
    /// List of available integers
    pub values: Vec<Word>,
    /// Target sum
    pub target: Word,
    /// Selection mask (which values to include)
    pub selection: Vec<bool>,
}

/// Output of subset sum (just the computed sum for verification)
pub struct SubsetSumOutput {
    pub computed_sum: Word,
}

impl SubsetSumBoojum {
    /// Pure witness computation - just Rust code, no constraints
    pub fn compute_witness_pure(input: &SubsetSumInput) -> SubsetSumOutput {
        let mut sum = 0u64;
        
        for i in 0..input.values.len() {
            if input.selection[i] {
                sum += input.values[i].0;
                assert!(sum <= u64::MAX, "Overflow in subset sum");
            }
        }
        
        assert_eq!(sum, input.target.0, "Sum doesn't match target");
        
        SubsetSumOutput {
            computed_sum: Word(sum),
        }
    }
    
    /// Tracked witness computation - records operations for constraint compilation
    pub fn compute_witness_tracked(ctx: &mut WitnessContext, input: &SubsetSumInput) -> SubsetSumOutput {
        let len = input.values.len();
        
        // Create tracked values (public inputs) as unsigned integers
        let values: Vec<_> = input.values.iter()
            .map(|&v| ctx.witness_uint(v))
            .collect();
        
        let target = ctx.witness_uint(input.target);
        
        // Create tracked selection (private witnesses) as bit patterns
        let selection: Vec<_> = input.selection.iter()
            .map(|&b| {
                let word = if b { Word::ALL_ONE } else { Word::ZERO };
                ctx.witness_bits(word)
            })
            .collect();
        
        // Mask values using selection (this is the actual computation)
        let mut values_masked = Vec::new();
        for i in 0..len {
            // Create bit mask from boolean (SAR by 63 to broadcast MSB)
            let bit_mask = ctx.sar(selection[i], 63);
            // Apply mask - need to convert uint to bits for AND operation
            let value_bits = ctx.as_bits_from_uint(values[i]);
            let value_masked_bits = ctx.and(value_bits, bit_mask);
            // Convert back to uint for addition
            let value_masked = ctx.as_uint(value_masked_bits);
            values_masked.push(value_masked);
        }
        
        // Compute sum with carry tracking
        let mut sum = ctx.zero_uint();
        let mut carry = ctx.zero_uint();
        
        for i in 0..len {
            let (new_sum, new_carry) = ctx.uint_add(sum, values_masked[i], carry);
            sum = new_sum;
            carry = new_carry;
            
            // Assert no overflow (carry MSB should be 0)
            let carry_bits = ctx.as_bits_from_uint(carry);
            let carry_msb = ctx.shr(carry_bits, 63);
            ctx.assert_zero_bits(carry_msb, &format!("no overflow at step {}", i));
        }
        
        // Assert sum matches target
        ctx.assert_eq_uint(sum, target, "sum matches target");
        
        SubsetSumOutput {
            computed_sum: sum.value,
        }
    }
}

/// Example of using the Boojum paradigm
pub fn example_usage() {
    // Problem instance
    let _input = SubsetSumInput {
        values: vec![Word(10), Word(20), Word(30), Word(40)],
        target: Word(50),
        selection: vec![true, false, true, false], // 10 + 30 = 40... wait this should be 50
    };
    
    // Phase 1: Pure witness computation (for testing/debugging)
    // This would panic because 10 + 30 != 50
    // let output = SubsetSumBoojum::compute_witness_pure(&input);
    
    // Fix the input
    let input = SubsetSumInput {
        values: vec![Word(10), Word(20), Word(30), Word(40)],
        target: Word(50),
        selection: vec![true, false, false, true], // 10 + 40 = 50
    };
    
    // Phase 1: Witness computation with tracking
    let mut witness_ctx = WitnessContext::new();
    let output = SubsetSumBoojum::compute_witness_tracked(&mut witness_ctx, &input);
    
    println!("Witness computation complete. Sum = {}", output.computed_sum.0);
    println!("Recorded {} operations", witness_ctx.operations().len());
    
    // Phase 2: Constraint compilation (DIRECT to backend types!)
    let mut compiler = ConstraintCompiler::new();
    compiler.compile(witness_ctx.operations());
    
    let (and_constraints, mul_constraints) = compiler.get_constraints();
    
    println!("Constraint compilation complete");
    println!("AND constraints: {}", and_constraints.len());
    println!("MUL constraints: {}", mul_constraints.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_subset_sum_boojum() {
        // Test case: select 10 and 40 to sum to 50
        let input = SubsetSumInput {
            values: vec![Word(10), Word(20), Word(30), Word(40)],
            target: Word(50),
            selection: vec![true, false, false, true],
        };
        
        // Test pure computation
        let output = SubsetSumBoojum::compute_witness_pure(&input);
        assert_eq!(output.computed_sum, Word(50));
        
        // Test tracked computation
        let mut ctx = WitnessContext::new();
        let tracked_output = SubsetSumBoojum::compute_witness_tracked(&mut ctx, &input);
        assert_eq!(tracked_output.computed_sum, Word(50));
        
        // Verify we recorded operations
        assert!(!ctx.operations().is_empty());
    }
    
    #[test]
    #[should_panic(expected = "Sum doesn't match target")]
    fn test_subset_sum_wrong_selection() {
        let input = SubsetSumInput {
            values: vec![Word(10), Word(20), Word(30), Word(40)],
            target: Word(50),
            selection: vec![true, true, false, false], // 10 + 20 = 30, not 50
        };
        
        SubsetSumBoojum::compute_witness_pure(&input);
    }
}