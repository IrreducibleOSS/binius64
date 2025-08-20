//! Typed constraint optimization and analysis
//!
//! This module provides pattern recognition and optimization for typed witness operations,
//! with explicit tracking of type interpretations for each operation.

use std::collections::{HashMap, HashSet};
use super::{Operation, FieldOp, UIntOp, BitsOp, FieldId, UIntId, BitsId};

/// Represents typed constraint patterns that can be optimized
#[derive(Debug, Clone)]
pub enum TypedConstraintPattern {
    /// Field accumulation: chain of field additions (XOR operations)
    FieldAccumulation {
        terms: Vec<FieldId>,
        result: FieldId,
    },
    /// Integer addition chain: sequential additions with carry propagation  
    UIntAdditionChain {
        inputs: Vec<UIntId>,
        output: UIntId,
    },
    /// Boolean masking: SAR followed by AND for conditional selection
    BooleanMask {
        boolean: BitsId,
        value: BitsId,
        masked: BitsId,
    },
}

/// Typed constraint optimizer that performs pattern-based optimizations
pub struct ConstraintOptimizer {
    patterns: Vec<TypedConstraintPattern>,
}

impl ConstraintOptimizer {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }
    
    /// Analyze typed operations to find optimization opportunities
    pub fn analyze(&mut self, operations: &[Operation]) {
        self.find_field_accumulations(operations);
        self.find_uint_addition_chains(operations);
        self.find_boolean_masks(operations);
    }
    
    /// Find field addition chains that can be optimized into XOR operands
    fn find_field_accumulations(&mut self, operations: &[Operation]) {
        let mut field_terms: HashMap<FieldId, Vec<FieldId>> = HashMap::new();
        
        for op in operations {
            if let Operation::Field(FieldOp::Add(a, b, result)) = op {
                let mut terms = Vec::new();
                
                // Check if operands are themselves field addition results
                if let Some(a_terms) = field_terms.get(a) {
                    terms.extend(a_terms.clone());
                } else {
                    terms.push(*a);
                }
                
                if let Some(b_terms) = field_terms.get(b) {
                    terms.extend(b_terms.clone());
                } else {
                    terms.push(*b);
                }
                
                field_terms.insert(*result, terms.clone());
                
                // If we have 3+ terms, it's worth optimizing
                if terms.len() >= 3 {
                    self.patterns.push(TypedConstraintPattern::FieldAccumulation {
                        terms,
                        result: *result,
                    });
                }
            }
        }
    }
    
    /// Find unsigned integer addition chains for multi-limb arithmetic
    fn find_uint_addition_chains(&mut self, operations: &[Operation]) {
        let mut current_chain = Vec::new();
        let mut chain_output = None;
        
        for op in operations {
            match op {
                Operation::UInt(UIntOp::Add(a, b, _cin, sum, _cout)) => {
                    if current_chain.is_empty() {
                        current_chain.push(*a);
                        current_chain.push(*b);
                    } else if Some(a) == chain_output.as_ref() || Some(b) == chain_output.as_ref() {
                        // Continue the chain
                        if Some(a) != chain_output.as_ref() {
                            current_chain.push(*a);
                        } else {
                            current_chain.push(*b);
                        }
                    } else {
                        // Chain broken, save if long enough
                        if current_chain.len() > 2 {
                            self.patterns.push(TypedConstraintPattern::UIntAdditionChain {
                                inputs: current_chain.clone(),
                                output: chain_output.unwrap(),
                            });
                        }
                        // Start new chain
                        current_chain = vec![*a, *b];
                    }
                    chain_output = Some(*sum);
                }
                _ => {
                    // Non-addition operation, save chain if exists
                    if current_chain.len() > 2 && chain_output.is_some() {
                        self.patterns.push(TypedConstraintPattern::UIntAdditionChain {
                            inputs: current_chain.clone(),
                            output: chain_output.unwrap(),
                        });
                    }
                    current_chain.clear();
                    chain_output = None;
                }
            }
        }
        
        // Save final chain if exists
        if current_chain.len() > 2 && chain_output.is_some() {
            self.patterns.push(TypedConstraintPattern::UIntAdditionChain {
                inputs: current_chain,
                output: chain_output.unwrap(),
            });
        }
    }
    
    /// Find boolean masking patterns: SAR followed by AND for conditional selection
    fn find_boolean_masks(&mut self, operations: &[Operation]) {
        // Track mask values generated by SAR operations
        let mut mask_values = std::collections::HashMap::new();
        
        for op in operations {
            match op {
                Operation::Bits(BitsOp::Sar(bool_id, 63, mask_id)) => {
                    // Record that mask_id is derived from bool_id with SAR 63
                    mask_values.insert(*mask_id, *bool_id);
                }
                Operation::Bits(BitsOp::And(a, b, result)) => {
                    // Check if either operand is a recorded mask
                    if let Some(bool_id) = mask_values.get(a) {
                        self.patterns.push(TypedConstraintPattern::BooleanMask {
                            boolean: *bool_id,
                            value: *b,
                            masked: *result,
                        });
                    } else if let Some(bool_id) = mask_values.get(b) {
                        self.patterns.push(TypedConstraintPattern::BooleanMask {
                            boolean: *bool_id,
                            value: *a,
                            masked: *result,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    
    /// Get optimization statistics
    pub fn stats(&self) -> TypedOptimizationStats {
        let mut stats = TypedOptimizationStats::default();
        
        for pattern in &self.patterns {
            match pattern {
                TypedConstraintPattern::FieldAccumulation { terms, .. } => {
                    stats.field_accumulations += 1;
                    stats.field_terms += terms.len();
                }
                TypedConstraintPattern::UIntAdditionChain { inputs, .. } => {
                    stats.uint_addition_chains += 1;
                    stats.uint_chain_length += inputs.len();
                }
                TypedConstraintPattern::BooleanMask { .. } => {
                    stats.boolean_masks += 1;
                }
            }
        }
        
        stats
    }
    
    /// Get detected patterns for analysis
    pub fn patterns(&self) -> &[TypedConstraintPattern] {
        &self.patterns
    }
}

#[derive(Default, Debug)]
pub struct TypedOptimizationStats {
    pub field_accumulations: usize,
    pub field_terms: usize,
    pub uint_addition_chains: usize,
    pub uint_chain_length: usize,
    pub boolean_masks: usize,
}

impl std::fmt::Display for TypedOptimizationStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Typed Constraint Optimization Statistics:")?;
        writeln!(f, "  Field accumulations: {} (total terms: {})", 
                 self.field_accumulations, self.field_terms)?;
        writeln!(f, "  UInt addition chains: {} (total length: {})", 
                 self.uint_addition_chains, self.uint_chain_length)?;
        writeln!(f, "  Boolean masks: {}", self.boolean_masks)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::witness::WitnessContext;
    use binius_core::Word;
    
    #[test]
    fn test_field_accumulation_detection() {
        let mut ctx = WitnessContext::new();
        
        // Create a field accumulation: a + b + c + d
        let a = ctx.witness_field(Word(1));
        let b = ctx.witness_field(Word(2));
        let c = ctx.witness_field(Word(3));
        let d = ctx.witness_field(Word(4));
        
        let ab = ctx.field_add(a, b);
        let abc = ctx.field_add(ab, c);
        let abcd = ctx.field_add(abc, d);
        
        let mut optimizer = ConstraintOptimizer::new();
        optimizer.analyze(ctx.operations());
        
        let stats = optimizer.stats();
        assert!(stats.field_accumulations > 0);
        assert!(stats.field_terms >= 4);  // a, b, c, d
    }
    
    #[test]
    fn test_uint_addition_chain_detection() {
        let mut ctx = WitnessContext::new();
        
        // Create a chain of integer additions
        let a = ctx.witness_uint(Word(100));
        let b = ctx.witness_uint(Word(200));
        let c = ctx.witness_uint(Word(300));
        let zero = ctx.zero_uint();
        
        let (ab, carry1) = ctx.uint_add(a, b, zero);
        let (abc, _carry2) = ctx.uint_add(ab, c, carry1);
        
        let mut optimizer = ConstraintOptimizer::new();
        optimizer.analyze(ctx.operations());
        
        let stats = optimizer.stats();
        // Should detect the addition chain
        assert!(stats.uint_addition_chains > 0 || stats.uint_chain_length > 0);
    }
    
    #[test]
    fn test_boolean_mask_detection() {
        let mut ctx = WitnessContext::new();
        
        // Create boolean masking pattern
        let bool_val = ctx.witness_bits(Word::ALL_ONE);  // -1 as signed
        let mask = ctx.sar(bool_val, 63);  // Spread sign bit
        let value = ctx.witness_bits(Word(0x123456789ABCDEF0));
        let selected = ctx.and(value, mask);
        
        let mut optimizer = ConstraintOptimizer::new();
        optimizer.analyze(ctx.operations());
        
        let stats = optimizer.stats();
        assert_eq!(stats.boolean_masks, 1);
    }
}