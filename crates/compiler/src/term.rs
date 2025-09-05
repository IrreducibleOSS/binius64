//! Constraint terms - atomic operations MORE GRANULAR than constraints
//!
//! Terms are individual operations (XOR, SHIFT, AND, MUL) that recipes 
//! combine into final constraints. They are NOT the same as core constraints!
//! 
//! In formal logic, a term is a basic building block - here our terms are
//! the atomic operations that compose to form constraint expressions.

use crate::expr::{Expr, ExprNode};
use crate::types::BitType;

// Import value types from core for term operands
use binius_core::constraint_system::{ValueIndex, ShiftVariant};

/// Atomic constraint term - individual operations that recipes combine
#[derive(Debug, Clone)]
pub enum Term {
    /// XOR operation (free - gets folded into operands)
    Xor {
        a: ValueIndex,
        b: ValueIndex,
        result: ValueIndex,
    },
    
    /// Shift operation (free - gets folded into operands as ShiftedValueIndex)
    Shift {
        input: ValueIndex,
        variant: ShiftVariant,
        amount: u8,
        result: ValueIndex,
    },
    
    /// NOT operation (free - can be represented as XOR with all-1s)
    Not {
        input: ValueIndex,
        result: ValueIndex,
    },
    
    /// AND operation (constraint-generating)
    And {
        a: ValueIndex,
        b: ValueIndex,
        result: ValueIndex,
    },
    
    /// MUL operation (constraint-generating)
    Mul {
        a: ValueIndex,
        b: ValueIndex,
        hi: ValueIndex,  // high 64 bits
        lo: ValueIndex,  // low 64 bits (result)
    },
}

/// Generate atomic terms from an expression tree
///
/// This creates the individual operation terms. Later, recipes will 
/// combine these terms into core constraints (AndConstraint, MulConstraint).
pub fn to_terms<T: BitType>(expr: &Expr<T>) -> Vec<Term> {
    let mut terms = Vec::new();
    let mut witness_counter = 0u32;
    
    generate_terms(&expr.inner, &mut terms, &mut witness_counter);
    terms
}

/// Assembles constraints from terms using delayed binding
/// 
/// Adapted from Beamish's delayed binding algorithm to work with terms.
/// The key insight: free terms get folded into operands, constraint terms generate constraints.
pub struct ConstraintAssembler {
    constraints: Vec<binius_core::constraint_system::AndConstraint>,
    mul_constraints: Vec<binius_core::constraint_system::MulConstraint>,
    next_temp: u32,
    
    // Track operand representations for each value
    operands: std::collections::HashMap<ValueIndex, Operand>,
}

// Core type aliases for cleaner code
type Operand = Vec<binius_core::constraint_system::ShiftedValueIndex>;
use binius_core::constraint_system::ShiftedValueIndex;

impl ConstraintAssembler {
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            mul_constraints: Vec::new(),
            next_temp: 1000, // Start temp IDs at 1000 like Beamish
            operands: std::collections::HashMap::new(),
        }
    }
    
    /// Assemble constraints from terms using delayed binding
    /// Returns (and_constraints, mul_constraints, unconsumed_terms)
    pub fn assemble_detailed(mut self, terms: &[Term]) -> (
        Vec<binius_core::constraint_system::AndConstraint>,
        Vec<binius_core::constraint_system::MulConstraint>,
        Vec<Term>
    ) {
        // First pass: process all terms
        for term in terms {
            self.process_term(term);
        }
        
        // Second pass: determine which terms are truly consumed
        let consumed = self.determine_consumed_terms(terms);
        
        // Collect unconsumed terms
        let unconsumed_terms: Vec<Term> = terms.iter()
            .zip(consumed.iter())
            .filter_map(|(term, &was_consumed)| {
                if was_consumed { None } else { Some(term.clone()) }
            })
            .collect();
        
        (self.constraints, self.mul_constraints, unconsumed_terms)
    }
    
    /// Assemble constraints from terms, panicking if any terms remain unconsumed
    /// This is the most common use case - all terms should be processed
    pub fn assemble(self, terms: &[Term]) -> (
        Vec<binius_core::constraint_system::AndConstraint>,
        Vec<binius_core::constraint_system::MulConstraint>
    ) {
        let (and_constraints, mul_constraints, unconsumed) = self.assemble_detailed(terms);
        
        if !unconsumed.is_empty() {
            panic!("ConstraintAssembler failed to consume {} terms: {:?}", 
                unconsumed.len(), unconsumed);
        }
        
        (and_constraints, mul_constraints)
    }
    
    fn process_term(&mut self, term: &Term) {
        match term {
            // Free terms - fold into operands, no constraints generated
            Term::Xor { a, b, result } => {
                let a_op = self.get_operand(*a);
                let b_op = self.get_operand(*b);
                let result_op = self.xor_operands(a_op, b_op);
                self.operands.insert(*result, result_op);
            }
            
            Term::Shift { input, variant, amount, result } => {
                let input_op = self.get_operand(*input);
                let result_op = self.shift_operand(input_op, *variant, *amount);
                self.operands.insert(*result, result_op);
            }
            
            Term::Not { input, result } => {
                let input_op = self.get_operand(*input);
                // NOT is XOR with all-ones (represented as constant in operand)
                let result_op = self.xor_with_constant(input_op, 0xFFFFFFFFFFFFFFFF);
                self.operands.insert(*result, result_op);
            }
            
            // Constraint terms - generate actual constraints
            Term::And { a, b, result } => {
                let a_op = self.get_operand(*a);
                let b_op = self.get_operand(*b);
                let result_op = vec![ShiftedValueIndex::plain(*result)];
                
                let constraint = binius_core::constraint_system::AndConstraint::abc(
                    a_op, b_op, result_op.clone()
                );
                self.constraints.push(constraint);
                self.operands.insert(*result, result_op);
            }
            
            Term::Mul { a, b, hi, lo } => {
                let a_op = self.get_operand(*a);
                let b_op = self.get_operand(*b);
                let hi_op = vec![ShiftedValueIndex::plain(*hi)];
                let lo_op = vec![ShiftedValueIndex::plain(*lo)];
                
                let constraint = binius_core::constraint_system::MulConstraint {
                    a: a_op,
                    b: b_op,
                    hi: hi_op.clone(),
                    lo: lo_op.clone(),
                };
                self.mul_constraints.push(constraint);
                self.operands.insert(*hi, hi_op);
                self.operands.insert(*lo, lo_op);
            }
        }
    }
    
    /// Determine which terms are truly consumed by analyzing usage patterns
    fn determine_consumed_terms(&self, terms: &[Term]) -> Vec<bool> {
        use std::collections::HashSet;
        
        // Track which ValueIndex results are used as inputs by other terms
        let mut used_values = HashSet::new();
        
        // Collect all input references from all terms
        for term in terms {
            match term {
                Term::Xor { a, b, .. } => {
                    used_values.insert(*a);
                    used_values.insert(*b);
                }
                Term::Shift { input, .. } => {
                    used_values.insert(*input);
                }
                Term::Not { input, .. } => {
                    used_values.insert(*input);
                }
                Term::And { a, b, .. } => {
                    used_values.insert(*a);
                    used_values.insert(*b);
                }
                Term::Mul { a, b, .. } => {
                    used_values.insert(*a);
                    used_values.insert(*b);
                }
            }
        }
        
        // A term is consumed if its result is used by another term OR if it's the final output
        // For now, we consider ANY term consumed only if its result is referenced somewhere
        // This will catch orphaned constraints too
        terms.iter().map(|term| {
            let result_value = match term {
                Term::Xor { result, .. } => *result,
                Term::Shift { result, .. } => *result,
                Term::Not { result, .. } => *result,
                Term::And { result, .. } => *result,
                Term::Mul { lo, .. } => *lo, // Use lo as the "result" for MUL
            };
            
            used_values.contains(&result_value)
        }).collect()
    }
    
    fn get_operand(&self, value: ValueIndex) -> Operand {
        self.operands.get(&value)
            .cloned()
            .unwrap_or_else(|| vec![ShiftedValueIndex::plain(value)])
    }
    
    fn xor_operands(&self, mut a: Operand, b: Operand) -> Operand {
        a.extend(b);
        a // XOR is just concatenation of shifted values
    }
    
    fn xor_with_constant(&self, mut operand: Operand, constant: u64) -> Operand {
        if constant != 0 {
            // Add constant as a special ValueIndex - constants are typically stored
            // at the beginning of the value vector in the ConstraintSystem
            // For now, create a ValueIndex that represents this constant
            // In a full implementation, we'd need a constant registry
            let constant_index = ValueIndex(constant as u32); // Simplified mapping
            operand.push(ShiftedValueIndex::plain(constant_index));
        }
        operand
    }
    
    fn shift_operand(&self, operand: Operand, variant: ShiftVariant, amount: u8) -> Operand {
        // Apply shift to each term in the operand
        operand.into_iter().map(|term| {
            // Compose shifts: if term already has a shift, we need to combine them
            // For now, implement simple cases - complex shift composition needs more logic
            match (term.shift_variant, variant, term.amount, amount as usize) {
                // No existing shift - apply new shift
                (ShiftVariant::Sll, ShiftVariant::Sll, 0, new_amount) => ShiftedValueIndex {
                    value_index: term.value_index,
                    shift_variant: variant,
                    amount: new_amount,
                },
                // Both shifts are same direction - combine amounts (with overflow check)
                (ShiftVariant::Sll, ShiftVariant::Sll, old_amount, new_amount) => {
                    let total = old_amount.saturating_add(new_amount).min(63);
                    ShiftedValueIndex {
                        value_index: term.value_index,
                        shift_variant: ShiftVariant::Sll,
                        amount: total,
                    }
                }
                // Different shift directions - need careful composition
                // For now, apply the new shift (this is simplified)
                _ => ShiftedValueIndex {
                    value_index: term.value_index,
                    shift_variant: variant,
                    amount: amount as usize,
                }
            }
        }).collect()
    }
}

fn generate_terms(_node: &ExprNode, _terms: &mut Vec<Term>, _witness_counter: &mut u32) {
    // This function is kept as a stub for now
    // In the current architecture, we focus on testing constraint assembly from manually-created terms
    // rather than automatic term generation from expressions
    
    // Future implementation would:
    // 1. Traverse expression tree
    // 2. Classify Call nodes by their compute function signature
    // 3. Generate appropriate terms (XOR, Shift, NOT are free; AND, MUL generate constraints)
    // 4. Assign ValueIndex IDs to intermediate results
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_core::constraint_system::{ValueIndex, ShiftVariant, ShiftedValueIndex, AndConstraint, MulConstraint};
    
    // Helper functions for building expected constraints
    fn expected_and_constraint(
        a_values: &[(u32, ShiftVariant, usize)],
        b_values: &[(u32, ShiftVariant, usize)], 
        c_values: &[(u32, ShiftVariant, usize)]
    ) -> AndConstraint {
        AndConstraint::abc(
            a_values.iter().map(|(idx, variant, amount)| ShiftedValueIndex {
                value_index: ValueIndex(*idx),
                shift_variant: *variant,
                amount: *amount,
            }),
            b_values.iter().map(|(idx, variant, amount)| ShiftedValueIndex {
                value_index: ValueIndex(*idx),
                shift_variant: *variant,
                amount: *amount,
            }),
            c_values.iter().map(|(idx, variant, amount)| ShiftedValueIndex {
                value_index: ValueIndex(*idx),
                shift_variant: *variant,
                amount: *amount,
            }),
        )
    }
    
    fn expected_mul_constraint(
        a_values: &[(u32, ShiftVariant, usize)],
        b_values: &[(u32, ShiftVariant, usize)],
        hi_values: &[(u32, ShiftVariant, usize)],
        lo_values: &[(u32, ShiftVariant, usize)]
    ) -> MulConstraint {
        MulConstraint {
            a: a_values.iter().map(|(idx, variant, amount)| ShiftedValueIndex {
                value_index: ValueIndex(*idx),
                shift_variant: *variant,
                amount: *amount,
            }).collect(),
            b: b_values.iter().map(|(idx, variant, amount)| ShiftedValueIndex {
                value_index: ValueIndex(*idx),
                shift_variant: *variant,
                amount: *amount,
            }).collect(),
            hi: hi_values.iter().map(|(idx, variant, amount)| ShiftedValueIndex {
                value_index: ValueIndex(*idx),
                shift_variant: *variant,
                amount: *amount,
            }).collect(),
            lo: lo_values.iter().map(|(idx, variant, amount)| ShiftedValueIndex {
                value_index: ValueIndex(*idx),
                shift_variant: *variant,
                amount: *amount,
            }).collect(),
        }
    }
    
    // Constraint comparison functions
    fn constraints_equal(actual: &AndConstraint, expected: &AndConstraint) -> bool {
        operands_equal(&actual.a, &expected.a) &&
        operands_equal(&actual.b, &expected.b) &&
        operands_equal(&actual.c, &expected.c)
    }
    
    fn mul_constraints_equal(actual: &MulConstraint, expected: &MulConstraint) -> bool {
        operands_equal(&actual.a, &expected.a) &&
        operands_equal(&actual.b, &expected.b) &&
        operands_equal(&actual.hi, &expected.hi) &&
        operands_equal(&actual.lo, &expected.lo)
    }
    
    fn operands_equal(actual: &Operand, expected: &Operand) -> bool {
        if actual.len() != expected.len() {
            return false;
        }
        
        // Sort both operands by (value_index, shift_variant, amount) for comparison
        let mut actual_sorted = actual.clone();
        let mut expected_sorted = expected.clone();
        
        let sort_key = |sv: &ShiftedValueIndex| (sv.value_index.0, sv.shift_variant as u8, sv.amount);
        actual_sorted.sort_by_key(sort_key);
        expected_sorted.sort_by_key(sort_key);
        
        for (a, e) in actual_sorted.iter().zip(expected_sorted.iter()) {
            if a.value_index != e.value_index ||
               !shift_variants_equal(a.shift_variant, e.shift_variant) ||
               a.amount != e.amount {
                return false;
            }
        }
        true
    }
    
    fn shift_variants_equal(a: ShiftVariant, b: ShiftVariant) -> bool {
        matches!((a, b), 
            (ShiftVariant::Sll, ShiftVariant::Sll) |
            (ShiftVariant::Slr, ShiftVariant::Slr) |
            (ShiftVariant::Sar, ShiftVariant::Sar)
        )
    }
    
    // Test vectors: term vectors → constraint vectors
    
    #[test]
    fn test_basic_term_constraint_vectors() {
        let test_cases = vec![
            // Test Vector 1: Free XOR term consumed by AND
            (
                "XOR term consumed by AND",
                vec![
                    Term::Xor {
                        a: ValueIndex(0),
                        b: ValueIndex(1), 
                        result: ValueIndex(2),
                    },
                    Term::And {
                        a: ValueIndex(2),  // Uses XOR result
                        b: ValueIndex(3),
                        result: ValueIndex(4),
                    }
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 0), (1, ShiftVariant::Sll, 0)], // XOR folded into operand
                    &[(3, ShiftVariant::Sll, 0)], // b (plain)
                    &[(4, ShiftVariant::Sll, 0)], // result
                )],
                vec![], // No MUL constraints
            ),
            
            // Test Vector 2: Basic AND constraint  
            (
                "AND term → single AND constraint",
                vec![Term::And {
                    a: ValueIndex(0),
                    b: ValueIndex(1),
                    result: ValueIndex(2),
                }],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 0)], // a (plain)
                    &[(1, ShiftVariant::Sll, 0)], // b (plain)
                    &[(2, ShiftVariant::Sll, 0)], // result (plain)
                )],
                vec![], // No MUL constraints
            ),
            
            // Test Vector 3: Free NOT term
            (
                "NOT term (free operation - XOR with all-1s)",
                vec![Term::Not {
                    input: ValueIndex(0),
                    result: ValueIndex(1),
                }],
                vec![], // NOT is free
                vec![], // No MUL constraints
            ),
            
            // Test Vector 4: Basic MUL constraint
            (
                "MUL term → single MUL constraint", 
                vec![Term::Mul {
                    a: ValueIndex(0),
                    b: ValueIndex(1),
                    hi: ValueIndex(2),
                    lo: ValueIndex(3),
                }],
                vec![], // No AND constraints
                vec![expected_mul_constraint(
                    &[(0, ShiftVariant::Sll, 0)], // a (plain)
                    &[(1, ShiftVariant::Sll, 0)], // b (plain)
                    &[(2, ShiftVariant::Sll, 0)], // hi (plain)
                    &[(3, ShiftVariant::Sll, 0)], // lo (plain)
                )],
            ),
            
            // Test Vector 5: Free SHIFT term
            (
                "SHIFT term (free operation - folds into operands)",
                vec![Term::Shift {
                    input: ValueIndex(0),
                    variant: ShiftVariant::Sll,
                    amount: 5,
                    result: ValueIndex(1),
                }],
                vec![], // Shift is free
                vec![], // No MUL constraints
            ),
        ];
        
        for (test_name, input_terms, expected_and, expected_mul) in test_cases {
            let assembler = ConstraintAssembler::new();
            let (actual_and, actual_mul, _unconsumed) = assembler.assemble_detailed(&input_terms);
            
            // Compare constraint vectors
            assert_eq!(actual_and.len(), expected_and.len(), 
                "{}: AND constraint count mismatch", test_name);
            assert_eq!(actual_mul.len(), expected_mul.len(),
                "{}: MUL constraint count mismatch", test_name);
                
            for (i, (actual, expected)) in actual_and.iter().zip(expected_and.iter()).enumerate() {
                assert!(constraints_equal(actual, expected),
                    "{}: AND constraint {} mismatch:\nActual: {:?}\nExpected: {:?}", 
                    test_name, i, actual, expected);
            }
            
            for (i, (actual, expected)) in actual_mul.iter().zip(expected_mul.iter()).enumerate() {
                assert!(mul_constraints_equal(actual, expected),
                    "{}: MUL constraint {} mismatch:\nActual: {:?}\nExpected: {:?}",
                    test_name, i, actual, expected);
            }
        }
    }
    
    #[test] 
    fn test_operand_building_vectors() {
        let test_cases = vec![
            // Test Vector 1: XOR chain builds single operand
            (
                "XOR chain → single operand with multiple terms",
                vec![
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(10) }, // temp1 = a ⊕ b
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(2), result: ValueIndex(11) }, // temp2 = temp1 ⊕ c
                    Term::And { a: ValueIndex(11), b: ValueIndex(3), result: ValueIndex(4) }, // result = temp2 & d
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 0), (1, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)], // a ⊕ b ⊕ c
                    &[(3, ShiftVariant::Sll, 0)], // d (plain)
                    &[(4, ShiftVariant::Sll, 0)], // result (plain)
                )],
                vec![],
            ),
            
            // Test Vector 2: Shift operations fold into operands
            (
                "Shift + AND → operand with shifted terms",
                vec![
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Sll, amount: 5, result: ValueIndex(10) },
                    Term::And { a: ValueIndex(10), b: ValueIndex(1), result: ValueIndex(2) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 5)], // a << 5
                    &[(1, ShiftVariant::Sll, 0)], // b (plain)
                    &[(2, ShiftVariant::Sll, 0)], // result (plain)
                )],
                vec![],
            ),
            
            // Test Vector 3: Mixed XOR and shift operations
            (
                "Shift + XOR + AND → operand with mixed terms",
                vec![
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Slr, amount: 3, result: ValueIndex(10) },
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(1), result: ValueIndex(11) },
                    Term::And { a: ValueIndex(11), b: ValueIndex(2), result: ValueIndex(3) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Slr, 3), (1, ShiftVariant::Sll, 0)], // (a >> 3) ⊕ b
                    &[(2, ShiftVariant::Sll, 0)], // c (plain)
                    &[(3, ShiftVariant::Sll, 0)], // result (plain)
                )],
                vec![],
            ),
            
            // Test Vector 4: Multiple separate constraints
            (
                "Multiple AND terms → multiple constraints",
                vec![
                    Term::And { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(10) },
                    Term::And { a: ValueIndex(2), b: ValueIndex(3), result: ValueIndex(11) },
                    Term::And { a: ValueIndex(10), b: ValueIndex(11), result: ValueIndex(4) },
                ],
                vec![
                    expected_and_constraint(&[(0, ShiftVariant::Sll, 0)], &[(1, ShiftVariant::Sll, 0)], &[(10, ShiftVariant::Sll, 0)]),
                    expected_and_constraint(&[(2, ShiftVariant::Sll, 0)], &[(3, ShiftVariant::Sll, 0)], &[(11, ShiftVariant::Sll, 0)]),
                    expected_and_constraint(&[(10, ShiftVariant::Sll, 0)], &[(11, ShiftVariant::Sll, 0)], &[(4, ShiftVariant::Sll, 0)]),
                ],
                vec![],
            ),
        ];
        
        for (test_name, input_terms, expected_and, expected_mul) in test_cases {
            let assembler = ConstraintAssembler::new();
            let (actual_and, actual_mul, _unconsumed) = assembler.assemble_detailed(&input_terms);
            
            // Compare constraint vectors
            assert_eq!(actual_and.len(), expected_and.len(),
                "{}: AND constraint count mismatch", test_name);
            assert_eq!(actual_mul.len(), expected_mul.len(),
                "{}: MUL constraint count mismatch", test_name);
                
            for (i, (actual, expected)) in actual_and.iter().zip(expected_and.iter()).enumerate() {
                assert!(constraints_equal(actual, expected),
                    "{}: AND constraint {} mismatch:\nActual: {:?}\nExpected: {:?}",
                    test_name, i, actual, expected);
            }
            
            for (i, (actual, expected)) in actual_mul.iter().zip(expected_mul.iter()).enumerate() {
                assert!(mul_constraints_equal(actual, expected),
                    "{}: MUL constraint {} mismatch:\nActual: {:?}\nExpected: {:?}",
                    test_name, i, actual, expected);
            }
        }
    }
    
    #[test]
    fn test_unconsumed_terms_tracking() {
        let test_cases = vec![
            // Test Vector 1: Complete circuit with internal consumption
            (
                "Complete internal circuit - XOR feeds AND, AND feeds another AND",
                vec![
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(2) },
                    Term::And { a: ValueIndex(2), b: ValueIndex(3), result: ValueIndex(4) },
                    Term::And { a: ValueIndex(4), b: ValueIndex(5), result: ValueIndex(6) },
                ],
                false, // Should fail - final AND result (6) is unused  
                1,     // Expected unconsumed count (the final AND)
            ),
            
            // Test Vector 2: Standalone XOR term (unconsumed)
            (
                "Standalone XOR term - should be unconsumed",
                vec![
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(2) },
                ],
                false, // Should fail (panic expected)
                1,     // Expected unconsumed count
            ),
            
            // Test Vector 3: Mix of consumed and unconsumed terms
            (
                "Mixed consumed/unconsumed terms",
                vec![
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(2) }, // Used in AND - consumed
                    Term::And { a: ValueIndex(2), b: ValueIndex(3), result: ValueIndex(4) }, // Result not used - unconsumed
                    Term::Shift { input: ValueIndex(5), variant: ShiftVariant::Sll, amount: 3, result: ValueIndex(6) }, // Standalone - unconsumed
                ],
                false, // Should fail (panic expected)  
                2,     // Expected unconsumed count (the AND result and the standalone shift)
            ),
            
            // Test Vector 4: Orphaned constraint result
            (
                "Orphaned AND result - constraint generated but result unused",
                vec![
                    Term::And { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(2) }, // Result not used anywhere
                ],
                false, // Should fail - AND result is orphaned
                1,     // The AND term should be unconsumed (its result goes nowhere)
            ),
            
            // Test Vector 5: Multiple standalone free terms
            (
                "Multiple standalone free terms", 
                vec![
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(2) },
                    Term::Not { input: ValueIndex(3), result: ValueIndex(4) },
                    Term::Shift { input: ValueIndex(5), variant: ShiftVariant::Slr, amount: 2, result: ValueIndex(6) },
                ],
                false, // Should fail
                3,     // All 3 terms unconsumed
            ),
        ];
        
        for (test_name, input_terms, should_succeed, expected_unconsumed_count) in test_cases {
            let assembler = ConstraintAssembler::new();
            
            // Test detailed API
            let (_, _, unconsumed) = assembler.assemble_detailed(&input_terms);
            assert_eq!(unconsumed.len(), expected_unconsumed_count,
                "{}: Unexpected unconsumed term count", test_name);
            
            // Test panic API
            let assembler2 = ConstraintAssembler::new();
            if should_succeed {
                // Should not panic
                let _result = assembler2.assemble(&input_terms);
            } else {
                // Should panic - test this carefully
                let result = std::panic::catch_unwind(|| {
                    assembler2.assemble(&input_terms)
                });
                assert!(result.is_err(), "{}: Expected panic but none occurred", test_name);
            }
        }
    }
    
    #[test]
    #[should_panic(expected = "ConstraintAssembler failed to consume")]
    fn test_panic_on_unconsumed_terms() {
        // Test that unconsumed terms cause a panic
        let assembler = ConstraintAssembler::new();
        
        // Create a standalone XOR term - its result is never used
        let terms = vec![
            Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(2) }
        ];
        
        // This SHOULD panic because the XOR result is never consumed
        let _result = assembler.assemble(&terms);
    }
    
    // Phase 4: Advanced Optimization Pattern Tests
    
    #[test]
    fn test_advanced_optimization_patterns() {
        let test_cases: Vec<(&str, Vec<Term>, Vec<AndConstraint>, Vec<MulConstraint>)> = vec![
            // Test Vector 1: XOR chain folding
            (
                "XOR chain folding - multiple XORs feeding into AND",
                vec![
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(10) },
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(2), result: ValueIndex(11) },
                    Term::Xor { a: ValueIndex(11), b: ValueIndex(3), result: ValueIndex(12) },
                    Term::And { a: ValueIndex(12), b: ValueIndex(4), result: ValueIndex(13) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 0), (1, ShiftVariant::Sll, 0), 
                      (2, ShiftVariant::Sll, 0), (3, ShiftVariant::Sll, 0)], // All XORs folded
                    &[(4, ShiftVariant::Sll, 0)],
                    &[(13, ShiftVariant::Sll, 0)],
                )],
                vec![], // No MUL constraints
            ),
            
            // Test Vector 2: Shift chain composition
            (
                "Shift chain composition - multiple shifts compose into single shift",
                vec![
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Sll, amount: 3, result: ValueIndex(10) },
                    Term::Shift { input: ValueIndex(10), variant: ShiftVariant::Sll, amount: 5, result: ValueIndex(11) },
                    Term::And { a: ValueIndex(11), b: ValueIndex(1), result: ValueIndex(12) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 8)], // Shifts composed: 3+5=8
                    &[(1, ShiftVariant::Sll, 0)],
                    &[(12, ShiftVariant::Sll, 0)],
                )],
                vec![], // No MUL constraints
            ),
            
            // Test Vector 3: NOT-XOR pattern optimization
            (
                "NOT folded with XOR - NOT is XOR with all-1s",
                vec![
                    Term::Not { input: ValueIndex(0), result: ValueIndex(10) },
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(1), result: ValueIndex(11) },
                    Term::And { a: ValueIndex(11), b: ValueIndex(2), result: ValueIndex(12) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 0), (u32::MAX, ShiftVariant::Sll, 0), (1, ShiftVariant::Sll, 0)], // NOT is XOR with all-1s constant
                    &[(2, ShiftVariant::Sll, 0)],
                    &[(12, ShiftVariant::Sll, 0)],
                )],
                vec![], // No MUL constraints  
            ),
            
            // Test Vector 4: Complex mixed operations
            (
                "Complex pattern - shift, XOR, NOT all feeding AND",
                vec![
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Slr, amount: 2, result: ValueIndex(10) },
                    Term::Not { input: ValueIndex(1), result: ValueIndex(11) },
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(11), result: ValueIndex(12) },
                    Term::Xor { a: ValueIndex(12), b: ValueIndex(2), result: ValueIndex(13) },
                    Term::And { a: ValueIndex(13), b: ValueIndex(3), result: ValueIndex(14) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Slr, 2), (1, ShiftVariant::Sll, 0), (u32::MAX, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)], // All free ops folded with NOT constant
                    &[(3, ShiftVariant::Sll, 0)],
                    &[(14, ShiftVariant::Sll, 0)],
                )],
                vec![], // No MUL constraints
            ),
            
            // Test Vector 5: Multiple independent AND constraints
            (
                "Multiple independent ANDs - each with its own operand chain",
                vec![
                    // First AND chain
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(10) },
                    Term::And { a: ValueIndex(10), b: ValueIndex(2), result: ValueIndex(11) },
                    // Second AND chain  
                    Term::Shift { input: ValueIndex(3), variant: ShiftVariant::Sar, amount: 4, result: ValueIndex(12) },
                    Term::And { a: ValueIndex(12), b: ValueIndex(4), result: ValueIndex(13) },
                ],
                vec![
                    expected_and_constraint(
                        &[(0, ShiftVariant::Sll, 0), (1, ShiftVariant::Sll, 0)],
                        &[(2, ShiftVariant::Sll, 0)],
                        &[(11, ShiftVariant::Sll, 0)],
                    ),
                    expected_and_constraint(
                        &[(3, ShiftVariant::Sar, 4)],
                        &[(4, ShiftVariant::Sll, 0)],
                        &[(13, ShiftVariant::Sll, 0)],
                    ),
                ],
                vec![], // No MUL constraints
            ),
        ];
        
        for (test_name, input_terms, expected_and, expected_mul) in test_cases {
            let assembler = ConstraintAssembler::new();
            let (actual_and, actual_mul, _unconsumed) = assembler.assemble_detailed(&input_terms);
            
            // Compare constraint counts
            assert_eq!(actual_and.len(), expected_and.len(), 
                "{}: AND constraint count mismatch", test_name);
            assert_eq!(actual_mul.len(), expected_mul.len(),
                "{}: MUL constraint count mismatch", test_name);
                
            // Compare individual constraints
            for (i, (actual, expected)) in actual_and.iter().zip(expected_and.iter()).enumerate() {
                assert!(constraints_equal(actual, expected),
                    "{}: AND constraint {} mismatch\nExpected: {:?}\nActual: {:?}", 
                    test_name, i, expected, actual);
            }
        }
    }
    
    // Phase 5: Integration Tests - Real Circuit Patterns
    
    #[test]
    fn test_integration_circuit_patterns() {
        let test_cases: Vec<(&str, Vec<Term>, Vec<AndConstraint>, Vec<MulConstraint>)> = vec![
            // Test Vector 1: SHA-256 Sigma0 pattern
            // Sigma0(x) = (x >>> 2) ⊕ (x >>> 13) ⊕ (x >>> 22)
            (
                "SHA-256 Sigma0 rotation pattern",
                vec![
                    // Create rotations
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Slr, amount: 2, result: ValueIndex(10) },
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Slr, amount: 13, result: ValueIndex(11) },
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Slr, amount: 22, result: ValueIndex(12) },
                    // XOR them together
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(11), result: ValueIndex(13) },
                    Term::Xor { a: ValueIndex(13), b: ValueIndex(12), result: ValueIndex(14) },
                    // Use in AND (as part of larger circuit)
                    Term::And { a: ValueIndex(14), b: ValueIndex(1), result: ValueIndex(15) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Slr, 2), (0, ShiftVariant::Slr, 13), (0, ShiftVariant::Slr, 22)], // All rotations folded
                    &[(1, ShiftVariant::Sll, 0)],
                    &[(15, ShiftVariant::Sll, 0)],
                )],
                vec![],
            ),
            
            // Test Vector 2: Bit manipulation pattern (extract and test bits)
            (
                "Bit extraction and testing pattern",
                vec![
                    // Shift to extract bit field
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Slr, amount: 16, result: ValueIndex(10) },
                    // Mask with constant (simulated as AND with input)
                    Term::And { a: ValueIndex(10), b: ValueIndex(1), result: ValueIndex(11) },
                    // Test against another value
                    Term::Xor { a: ValueIndex(11), b: ValueIndex(2), result: ValueIndex(12) },
                    Term::And { a: ValueIndex(12), b: ValueIndex(3), result: ValueIndex(13) },
                ],
                vec![
                    expected_and_constraint(
                        &[(0, ShiftVariant::Slr, 16)],
                        &[(1, ShiftVariant::Sll, 0)],
                        &[(11, ShiftVariant::Sll, 0)],
                    ),
                    expected_and_constraint(
                        &[(11, ShiftVariant::Sll, 0), (2, ShiftVariant::Sll, 0)],
                        &[(3, ShiftVariant::Sll, 0)],
                        &[(13, ShiftVariant::Sll, 0)],
                    ),
                ],
                vec![],
            ),
            
            // Test Vector 3: Conditional select pattern
            // result = (cond & a) | (~cond & b) = (cond & a) ⊕ (~cond & b)
            (
                "Conditional select pattern",
                vec![
                    // First branch: cond & a
                    Term::And { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(10) },
                    // Second branch: ~cond & b
                    Term::Not { input: ValueIndex(0), result: ValueIndex(11) },
                    Term::And { a: ValueIndex(11), b: ValueIndex(2), result: ValueIndex(12) },
                    // Combine branches
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(12), result: ValueIndex(13) },
                    // Use result
                    Term::And { a: ValueIndex(13), b: ValueIndex(3), result: ValueIndex(14) },
                ],
                vec![
                    expected_and_constraint(
                        &[(0, ShiftVariant::Sll, 0)],
                        &[(1, ShiftVariant::Sll, 0)],
                        &[(10, ShiftVariant::Sll, 0)],
                    ),
                    expected_and_constraint(
                        &[(0, ShiftVariant::Sll, 0), (u32::MAX, ShiftVariant::Sll, 0)], // NOT as XOR with constant
                        &[(2, ShiftVariant::Sll, 0)],
                        &[(12, ShiftVariant::Sll, 0)],
                    ),
                    expected_and_constraint(
                        &[(10, ShiftVariant::Sll, 0), (12, ShiftVariant::Sll, 0)],
                        &[(3, ShiftVariant::Sll, 0)],
                        &[(14, ShiftVariant::Sll, 0)],
                    ),
                ],
                vec![],
            ),
            
            // Test Vector 4: Multi-word operation simulation
            (
                "Multi-word carry chain simulation",
                vec![
                    // Word 0 operation
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(10) },
                    Term::And { a: ValueIndex(0), b: ValueIndex(1), result: ValueIndex(11) }, // Carry generation
                    
                    // Word 1 operation with carry
                    Term::Xor { a: ValueIndex(2), b: ValueIndex(3), result: ValueIndex(12) },
                    Term::Xor { a: ValueIndex(12), b: ValueIndex(11), result: ValueIndex(13) }, // Add carry
                    Term::And { a: ValueIndex(13), b: ValueIndex(4), result: ValueIndex(14) }, // Final result
                ],
                vec![
                    expected_and_constraint(
                        &[(0, ShiftVariant::Sll, 0)],
                        &[(1, ShiftVariant::Sll, 0)],
                        &[(11, ShiftVariant::Sll, 0)],
                    ),
                    expected_and_constraint(
                        &[(2, ShiftVariant::Sll, 0), (3, ShiftVariant::Sll, 0), (11, ShiftVariant::Sll, 0)],
                        &[(4, ShiftVariant::Sll, 0)],
                        &[(14, ShiftVariant::Sll, 0)],
                    ),
                ],
                vec![],
            ),
        ];
        
        for (test_name, input_terms, expected_and, expected_mul) in test_cases {
            let assembler = ConstraintAssembler::new();
            let (actual_and, actual_mul, _unconsumed) = assembler.assemble_detailed(&input_terms);
            
            assert_eq!(actual_and.len(), expected_and.len(), 
                "{}: AND constraint count mismatch", test_name);
            assert_eq!(actual_mul.len(), expected_mul.len(),
                "{}: MUL constraint count mismatch", test_name);
                
            for (i, (actual, expected)) in actual_and.iter().zip(expected_and.iter()).enumerate() {
                assert!(constraints_equal(actual, expected),
                    "{}: AND constraint {} mismatch\nExpected: {:?}\nActual: {:?}", 
                    test_name, i, expected, actual);
            }
        }
    }
    
    // Phase 6: Edge Cases and Error Handling Tests
    
    #[test] 
    fn test_edge_cases_and_special_patterns() {
        let test_cases: Vec<(&str, Vec<Term>, Vec<AndConstraint>, Vec<MulConstraint>)> = vec![
            // Test Vector 1: Empty term list
            (
                "Empty term list - no constraints generated",
                vec![],
                vec![],
                vec![],
            ),
            
            // Test Vector 2: Single MUL constraint
            (
                "Single MUL constraint",
                vec![
                    Term::Mul { a: ValueIndex(0), b: ValueIndex(1), hi: ValueIndex(2), lo: ValueIndex(3) },
                ],
                vec![],
                vec![MulConstraint {
                    a: vec![ShiftedValueIndex::plain(ValueIndex(0))],
                    b: vec![ShiftedValueIndex::plain(ValueIndex(1))],
                    hi: vec![ShiftedValueIndex::plain(ValueIndex(2))],
                    lo: vec![ShiftedValueIndex::plain(ValueIndex(3))],
                }],
            ),
            
            // Test Vector 3: XOR with itself (currently NOT optimized to zero)
            (
                "XOR with itself - currently not optimized",
                vec![
                    Term::Xor { a: ValueIndex(0), b: ValueIndex(0), result: ValueIndex(1) },
                    Term::And { a: ValueIndex(1), b: ValueIndex(2), result: ValueIndex(3) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 0), (0, ShiftVariant::Sll, 0)], // Currently XOR with self isn't optimized
                    &[(2, ShiftVariant::Sll, 0)],
                    &[(3, ShiftVariant::Sll, 0)],
                )],
                vec![],
            ),
            
            // Test Vector 4: Maximum shift amounts (63 bits)
            (
                "Maximum shift amounts",
                vec![
                    Term::Shift { input: ValueIndex(0), variant: ShiftVariant::Sll, amount: 63, result: ValueIndex(1) },
                    Term::Shift { input: ValueIndex(2), variant: ShiftVariant::Slr, amount: 63, result: ValueIndex(3) },
                    Term::Shift { input: ValueIndex(4), variant: ShiftVariant::Sar, amount: 63, result: ValueIndex(5) },
                    Term::Xor { a: ValueIndex(1), b: ValueIndex(3), result: ValueIndex(6) },
                    Term::Xor { a: ValueIndex(6), b: ValueIndex(5), result: ValueIndex(7) },
                    Term::And { a: ValueIndex(7), b: ValueIndex(8), result: ValueIndex(9) },
                ],
                vec![expected_and_constraint(
                    &[(0, ShiftVariant::Sll, 63), (2, ShiftVariant::Slr, 63), (4, ShiftVariant::Sar, 63)],
                    &[(8, ShiftVariant::Sll, 0)],
                    &[(9, ShiftVariant::Sll, 0)],
                )],
                vec![],
            ),
            
            // Test Vector 5: Mixed MUL and AND constraints
            (
                "Mixed MUL and AND constraints",
                vec![
                    // MUL operation
                    Term::Mul { a: ValueIndex(0), b: ValueIndex(1), hi: ValueIndex(10), lo: ValueIndex(11) },
                    // Use MUL results in XOR
                    Term::Xor { a: ValueIndex(10), b: ValueIndex(11), result: ValueIndex(12) },
                    // AND with another value
                    Term::And { a: ValueIndex(12), b: ValueIndex(2), result: ValueIndex(13) },
                ],
                vec![expected_and_constraint(
                    &[(10, ShiftVariant::Sll, 0), (11, ShiftVariant::Sll, 0)],
                    &[(2, ShiftVariant::Sll, 0)],
                    &[(13, ShiftVariant::Sll, 0)],
                )],
                vec![MulConstraint {
                    a: vec![ShiftedValueIndex::plain(ValueIndex(0))],
                    b: vec![ShiftedValueIndex::plain(ValueIndex(1))],
                    hi: vec![ShiftedValueIndex::plain(ValueIndex(10))],
                    lo: vec![ShiftedValueIndex::plain(ValueIndex(11))],
                }],
            ),
            
            // Test Vector 6: Deep nesting of free operations
            (
                "Deep nesting of free operations",
                vec![
                    Term::Not { input: ValueIndex(0), result: ValueIndex(10) },
                    Term::Not { input: ValueIndex(10), result: ValueIndex(11) }, // Double NOT
                    Term::Xor { a: ValueIndex(11), b: ValueIndex(1), result: ValueIndex(12) },
                    Term::Shift { input: ValueIndex(12), variant: ShiftVariant::Sll, amount: 5, result: ValueIndex(13) },
                    Term::Xor { a: ValueIndex(13), b: ValueIndex(2), result: ValueIndex(14) },
                    Term::Not { input: ValueIndex(14), result: ValueIndex(15) },
                    Term::And { a: ValueIndex(15), b: ValueIndex(3), result: ValueIndex(16) },
                ],
                vec![expected_and_constraint(
                    // NOT: 0 XOR all-1s, NOT again: (0 XOR all-1s) XOR all-1s = 0 XOR all-1s XOR all-1s
                    // Then XOR with 1, shift left 5, XOR with 2, NOT
                    &[(0, ShiftVariant::Sll, 5), (u32::MAX, ShiftVariant::Sll, 5), (u32::MAX, ShiftVariant::Sll, 5), 
                      (1, ShiftVariant::Sll, 5), (2, ShiftVariant::Sll, 0), (u32::MAX, ShiftVariant::Sll, 0)],
                    &[(3, ShiftVariant::Sll, 0)],
                    &[(16, ShiftVariant::Sll, 0)],
                )],
                vec![],
            ),
        ];
        
        for (test_name, input_terms, expected_and, expected_mul) in test_cases {
            let assembler = ConstraintAssembler::new();
            let (actual_and, actual_mul, _unconsumed) = assembler.assemble_detailed(&input_terms);
            
            assert_eq!(actual_and.len(), expected_and.len(), 
                "{}: AND constraint count mismatch", test_name);
            assert_eq!(actual_mul.len(), expected_mul.len(),
                "{}: MUL constraint count mismatch", test_name);
                
            for (i, (actual, expected)) in actual_and.iter().zip(expected_and.iter()).enumerate() {
                assert!(constraints_equal(actual, expected),
                    "{}: AND constraint {} mismatch\nExpected: {:?}\nActual: {:?}", 
                    test_name, i, expected, actual);
            }
            
            for (i, (actual, expected)) in actual_mul.iter().zip(expected_mul.iter()).enumerate() {
                assert!(mul_constraints_equal(actual, expected),
                    "{}: MUL constraint {} mismatch\nExpected: {:?}\nActual: {:?}", 
                    test_name, i, expected, actual);
            }
        }
    }
    
}