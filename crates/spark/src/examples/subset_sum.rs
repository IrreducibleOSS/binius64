//! Subset Sum in the Spark paradigm
//!
//! This demonstrates the subset sum problem using the Spark witness-first approach.

use binius_core::Word;
use crate::witness::WitnessContext;

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

/// Spark implementation - pure witness computation (no tracking)
pub fn reference_subset_sum(input: &SubsetSumInput) -> SubsetSumOutput {
    let mut sum = 0u64;
    
    for i in 0..input.values.len() {
        if input.selection[i] {
            sum += input.values[i].0;
            // sum is u64, so overflow is already checked by Rust
        }
    }
    
    assert_eq!(sum, input.target.0, "Sum doesn't match target");
    
    SubsetSumOutput {
        computed_sum: Word(sum),
    }
}

/// Spark implementation - tracked witness computation
pub fn spark_subset_sum(ctx: &mut WitnessContext, input: &SubsetSumInput) -> SubsetSumOutput {
    let len = input.values.len();
    
    // Create tracked values as unsigned integers
    let values: Vec<_> = input.values.iter()
        .map(|&v| ctx.witness_uint(v))
        .collect();
    
    let target = ctx.witness_uint(input.target);
    
    // Create tracked selection as bit patterns
    let selection: Vec<_> = input.selection.iter()
        .map(|&b| {
            let word = if b { Word::ALL_ONE } else { Word::ZERO };
            ctx.witness_bits(word)
        })
        .collect();
    
    // Mask values using selection
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
        let (new_sum, new_carry) = ctx.add_with_carry(sum, values_masked[i], carry);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::ConstraintCompiler;
    
    #[test]
    fn test_subset_sum_spark() {
        // Test case: select 10 and 40 to sum to 50
        let input = SubsetSumInput {
            values: vec![Word(10), Word(20), Word(30), Word(40)],
            target: Word(50),
            selection: vec![true, false, false, true],
        };
        
        // Test pure computation
        let output = reference_subset_sum(&input);
        assert_eq!(output.computed_sum, Word(50));
        
        // Test tracked computation
        let mut ctx = WitnessContext::new();
        let tracked_output = spark_subset_sum(&mut ctx, &input);
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
        
        reference_subset_sum(&input);
    }
    
    #[test]
    fn test_subset_sum_constraints() {
        let input = SubsetSumInput {
            values: vec![Word(1), Word(2), Word(3), Word(4)],
            target: Word(7),
            selection: vec![false, false, true, true], // 3 + 4 = 7
        };
        
        let mut ctx = WitnessContext::new();
        let _ = spark_subset_sum(&mut ctx, &input);
        
        // Compile to constraints
        let mut compiler = ConstraintCompiler::new();
        compiler.compile(ctx.operations());
        let (and_constraints, mul_constraints) = compiler.get_constraints();
        
        // Should generate AND constraints for masking and carry
        assert!(!and_constraints.is_empty());
        assert_eq!(mul_constraints.len(), 0, "Subset sum doesn't need MUL constraints");
    }
}