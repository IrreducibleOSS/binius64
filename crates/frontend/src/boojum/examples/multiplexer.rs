//! Multiplexer circuit in the Boojum paradigm
//!
//! This demonstrates how a simple selection circuit (multiplexer) looks in our new architecture.
//! Compare with circuits/multiplexer.rs to see the difference.

use binius_core::Word;
use crate::boojum::{TrackedWord, witness::WitnessContext, BitsValue};

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

/// A simple 2-to-1 multiplexer in Boojum paradigm
pub struct Mux2Boojum;

impl Mux2Boojum {
    /// Pure witness computation - just selects based on MSB
    pub fn compute_witness_pure(a: Word, b: Word, sel: Word) -> Word {
        // If MSB of sel is 1, select b, otherwise select a
        if sel.0 >> 63 == 1 {
            b
        } else {
            a
        }
    }
    
    /// Tracked witness computation for 2-to-1 mux
    pub fn compute_witness_tracked(
        ctx: &mut WitnessContext,
        a: BitsValue,
        b: BitsValue,
        sel: BitsValue,
    ) -> BitsValue {
        // The select gate in CircuitBuilder uses MSB for selection
        // We need to implement: out = (sel_msb & b) | (~sel_msb & a)
        // Which is equivalent to: out = a ^ ((a ^ b) & sel_msb_mask)
        
        // Create MSB mask by arithmetic right shift
        let sel_mask = ctx.sar(sel, 63);
        
        // Compute a XOR b (field addition interpreted as bits)
        let a_field = ctx.as_field(a);
        let b_field = ctx.as_field(b);
        let diff_field = ctx.field_add(a_field, b_field);
        let diff = ctx.as_bits(diff_field);
        
        // Mask the difference
        let masked_diff = ctx.and(diff, sel_mask);
        
        // XOR with a to get the result (field addition again)
        let a_field2 = ctx.as_field(a);
        let masked_diff_field = ctx.as_field(masked_diff);
        let result_field = ctx.field_add(a_field2, masked_diff_field);
        ctx.as_bits(result_field)
    }
}

/// Multi-input multiplexer in Boojum paradigm
pub struct MultiplexerBoojum;

impl MultiplexerBoojum {
    /// Pure witness computation - no constraints, just Rust
    pub fn compute_witness_pure(input: &MultiplexerInput) -> MultiplexerOutput {
        let n = input.inputs.len();
        assert!(n > 0, "Input vector must not be empty");
        
        // Extract index from selector (use lower bits)
        let index = (input.selector.0 as usize) & (n - 1).min(usize::MAX);
        let selected_index = index.min(n - 1);
        
        MultiplexerOutput {
            selected: input.inputs[selected_index],
        }
    }
    
    /// Tracked witness computation - builds a binary tree of selections
    pub fn compute_witness_tracked(
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
            // We want bit 0 for level 0, bit 1 for level 1, etc.
            // So we shift left to put the desired bit in MSB position
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
                    let selected = Mux2Boojum::compute_witness_tracked(
                        ctx,
                        current_level[i],
                        current_level[i + 1],
                        sel_bit,
                    );
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
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mux2_boojum() {
        let a = Word(42);
        let b = Word(99);
        
        // Test with selector MSB = 0 (select a)
        let sel0 = Word(0);
        assert_eq!(Mux2Boojum::compute_witness_pure(a, b, sel0), a);
        
        // Test with selector MSB = 1 (select b)
        let sel1 = Word(0x8000_0000_0000_0000);
        assert_eq!(Mux2Boojum::compute_witness_pure(a, b, sel1), b);
        
        // Test tracked version
        let mut ctx = WitnessContext::new();
        let a_t = ctx.witness_bits(a);
        let b_t = ctx.witness_bits(b);
        let sel_t = ctx.witness_bits(sel1);
        
        let result = Mux2Boojum::compute_witness_tracked(&mut ctx, a_t, b_t, sel_t);
        assert_eq!(result.value, b);
    }
    
    #[test]
    fn test_multiplexer_4_inputs() {
        let input = MultiplexerInput {
            inputs: vec![Word(10), Word(20), Word(30), Word(40)],
            selector: Word(2), // Select index 2 (value 30)
        };
        
        // Test pure computation
        let output = MultiplexerBoojum::compute_witness_pure(&input);
        assert_eq!(output.selected, Word(30));
        
        // Test tracked computation
        let mut ctx = WitnessContext::new();
        let tracked_output = MultiplexerBoojum::compute_witness_tracked(&mut ctx, &input);
        assert_eq!(tracked_output.selected, Word(30));
        
        // Verify operations were recorded
        assert!(!ctx.operations().is_empty());
        println!("4-input mux generated {} operations", ctx.operations().len());
    }
    
    #[test]
    fn test_multiplexer_power_of_two() {
        let input = MultiplexerInput {
            inputs: vec![Word(1), Word(2), Word(3), Word(4), Word(5), Word(6), Word(7), Word(8)],
            selector: Word(5), // Select index 5 (value 6)
        };
        
        let output = MultiplexerBoojum::compute_witness_pure(&input);
        assert_eq!(output.selected, Word(6));
        
        let mut ctx = WitnessContext::new();
        let tracked_output = MultiplexerBoojum::compute_witness_tracked(&mut ctx, &input);
        assert_eq!(tracked_output.selected, Word(6));
    }
}