//! Multiplexer in the Spark paradigm
//!
//! This example shows multiplexer circuits using the Spark witness-first approach.

use binius_core::Word;
use crate::{witness::WitnessContext, BitsValue};

/// Input to a multiplexer
pub struct MultiplexerInput {
    /// Values to select from
    pub inputs: Vec<Word>,
    /// Selector index (only lower bits used)
    pub selector: Word,
}

/// Output of multiplexer (the selected value)
pub struct MultiplexerOutput {
    pub selected: Word,
}


/// Spark 2-to-1 mux - pure witness computation
pub fn reference_mux2(a: Word, b: Word, sel: Word) -> Word {
    // If MSB of sel is 1, select b, otherwise select a
    if sel.0 >> 63 == 1 {
        b
    } else {
        a
    }
}

/// Spark 2-to-1 mux - tracked witness computation
pub fn spark_mux2(
    ctx: &mut WitnessContext,
    a: BitsValue,
    b: BitsValue,
    sel: BitsValue,
) -> BitsValue {
    // Create MSB mask by arithmetic right shift
    let sel_mask = ctx.sar(sel, 63);
    
    // Compute a XOR b (field addition interpreted as bits)
    let a_field = ctx.as_field(a);
    let b_field = ctx.as_field(b);
    let diff_field = ctx.add(a_field, b_field);
    let diff = ctx.as_bits(diff_field);
    
    // Mask the difference
    let masked_diff = ctx.and(diff, sel_mask);
    
    // XOR with a to get the result (field addition again)
    let a_field2 = ctx.as_field(a);
    let masked_diff_field = ctx.as_field(masked_diff);
    let result_field = ctx.add(a_field2, masked_diff_field);
    ctx.as_bits(result_field)
}

/// Spark multiplexer - pure witness computation
pub fn reference_multiplexer(input: &MultiplexerInput) -> MultiplexerOutput {
    let n = input.inputs.len();
    assert!(n > 0, "Input vector must not be empty");
    
    // Extract index from selector (use lower bits)
    let index = (input.selector.0 as usize) & (n - 1).min(usize::MAX);
    let selected_index = index.min(n - 1);
    
    MultiplexerOutput {
        selected: input.inputs[selected_index],
    }
}

/// Spark multiplexer - tracked witness computation
pub fn spark_multiplexer(
    ctx: &mut WitnessContext,
    input: &MultiplexerInput,
) -> MultiplexerOutput {
    let n = input.inputs.len();
    assert!(n > 0, "Input vector must not be empty");
    
    // Create tracked values for inputs as bit patterns
    let mut current_level: Vec<BitsValue> = input.inputs
        .iter()
        .map(|&val| ctx.witness_bits(val))
        .collect();
    
    let selector = ctx.witness_bits(input.selector);
    
    // Build multiplexer tree level by level
    let num_levels = (n as f64).log2().ceil() as u32;
    
    for bit_level in 0..num_levels {
        if current_level.len() == 1 {
            break;
        }
        
        // Shift selector to get the bit for this level
        let shift_amount = 63 - bit_level;
        let sel_bit = if shift_amount > 0 {
            ctx.shl(selector, shift_amount)
        } else {
            selector
        };
        
        // Process pairs at current level
        let mut next_level = Vec::new();
        let mut i = 0;
        
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                // We have a pair - mux them
                let selected = spark_mux2(ctx, current_level[i], current_level[i + 1], sel_bit);
                next_level.push(selected);
                i += 2;
            } else {
                // Odd one out - carry forward
                next_level.push(current_level[i]);
                i += 1;
            }
        }
        
        current_level = next_level;
    }
    
    assert_eq!(current_level.len(), 1, "Should have exactly one output");
    
    MultiplexerOutput {
        selected: current_level[0].value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::ConstraintCompiler;
    
    #[test]
    fn test_mux2_spark() {
        let a = Word(42);
        let b = Word(99);
        
        // Test with selector MSB = 0 (select a)
        let sel0 = Word(0);
        assert_eq!(reference_mux2(a, b, sel0), a);
        
        // Test with selector MSB = 1 (select b)
        let sel1 = Word(0x8000_0000_0000_0000);
        assert_eq!(reference_mux2(a, b, sel1), b);
        
        // Test tracked version
        let mut ctx = WitnessContext::new();
        let a_t = ctx.witness_bits(a);
        let b_t = ctx.witness_bits(b);
        let sel_t = ctx.witness_bits(sel1);
        
        let result = spark_mux2(&mut ctx, a_t, b_t, sel_t);
        assert_eq!(result.value, b);
    }
    
    #[test]
    fn test_multiplexer_4_inputs() {
        let input = MultiplexerInput {
            inputs: vec![Word(10), Word(20), Word(30), Word(40)],
            selector: Word(2), // Select index 2 (value 30)
        };
        
        // Test pure computation
        let output = reference_multiplexer(&input);
        assert_eq!(output.selected, Word(30));
        
        // Test tracked computation
        let mut ctx = WitnessContext::new();
        let tracked_output = spark_multiplexer(&mut ctx, &input);
        assert_eq!(tracked_output.selected, Word(30));
        
        // Verify operations were recorded
        assert!(!ctx.operations().is_empty());
    }
    
    #[test]
    fn test_multiplexer_constraints() {
        let input = MultiplexerInput {
            inputs: vec![Word(1), Word(2), Word(3), Word(4)],
            selector: Word(3), // Select index 3 (value 4)
        };
        
        let mut ctx = WitnessContext::new();
        let _ = spark_multiplexer(&mut ctx, &input);
        
        // Compile to constraints
        let mut compiler = ConstraintCompiler::new();
        compiler.compile(ctx.operations());
        let (and_constraints, mul_constraints) = compiler.get_constraints();
        
        // Should generate AND constraints for selection logic
        assert!(!and_constraints.is_empty());
        assert_eq!(mul_constraints.len(), 0, "Multiplexer doesn't use MUL constraints");
    }
}