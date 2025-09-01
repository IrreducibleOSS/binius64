//! Multi-constraint optimization templates

use crate::expr::ExprNode;
use crate::constraints::Constraint;
use std::rc::Rc;

/// Template for recognizing and optimizing complex patterns
pub trait ConstraintTemplate {
    /// Check if this template matches the expression
    fn matches(&self, expr: &ExprNode) -> bool;
    
    /// Generate optimized constraints for the matched pattern
    /// Returns None if template doesn't apply or can't optimize
    fn generate(&self, expr: &ExprNode, next_temp: &mut u32) -> Option<Vec<Constraint>>;
}

/// Template for optimizing carry chains in additions
pub struct CarryChainTemplate;

impl ConstraintTemplate for CarryChainTemplate {
    fn matches(&self, expr: &ExprNode) -> bool {
        // Look for patterns like Add(Add(Add(a, b), c), d)
        // Need at least 3 values to make fusion worthwhile
        detect_operation_chain(expr).is_some_and(|chain| chain.len() >= 3)
    }
    
    fn generate(&self, expr: &ExprNode, next_temp: &mut u32) -> Option<Vec<Constraint>> {
        // Implement carry chain fusion using carry-save addition
        if let Some(chain) = detect_operation_chain(expr) {
            if chain.len() >= 3 {
                use crate::constraints::{Operand, ShiftedValue, ShiftOp};
                
                // Build operands for all values in the chain
                let operands: Vec<Operand> = chain.iter()
                    .map(build_operand)
                    .collect();
                
                let mut constraints = Vec::new();
                
                // Carry-save addition: maintain partial sums and carries separately
                // This avoids ripple-carry propagation until the final step
                
                // For chain a+b+c+d, compute:
                // 1. Partial sums without carry propagation
                // 2. Carry bits for each position
                // 3. Final propagation only at the end
                
                // Start with first two operands
                let mut partial_sum = operands[0].clone().xor(operands[1].clone());
                let mut carry_save = {
                    let carry_temp = *next_temp;
                    *next_temp += 1;
                    
                    // Initial carry from a & b
                    constraints.push(Constraint::And {
                        a: operands[0].clone(),
                        b: operands[1].clone(),
                        c: Operand::from_value(carry_temp),
                    });
                    
                    Operand::from_value(carry_temp)
                };
                
                // Process remaining operands with carry-save
                for i in 2..operands.len() {
                    let next_val = &operands[i];
                    
                    // Three-way XOR for new partial sum
                    let new_partial = partial_sum.clone().xor(next_val.clone()).xor(carry_save.clone());
                    
                    // New carry-save: majority of three inputs
                    let new_carry_temp = *next_temp;
                    *next_temp += 1;
                    
                    // Majority function as single constraint
                    // Uses the identity: Maj(a,b,c) = (a⊕c)&(b⊕c)⊕c
                    let a_xor_c = partial_sum.clone().xor(carry_save.clone());
                    let b_xor_c = next_val.clone().xor(carry_save.clone());
                    
                    constraints.push(Constraint::And {
                        a: a_xor_c,
                        b: b_xor_c,
                        c: carry_save.clone().xor(Operand::from_value(new_carry_temp)),
                    });
                    
                    partial_sum = new_partial;
                    carry_save = Operand::from_value(new_carry_temp);
                }
                
                // Final carry propagation (only once at the end)
                let result = *next_temp;
                *next_temp += 1;
                
                // Shift carry left by 1 for final addition
                let carry_shifted = if carry_save.terms.len() == 1 && carry_save.constant.is_none() {
                    // Simple case: single term
                    Operand {
                        terms: vec![ShiftedValue {
                            value_id: carry_save.terms[0].value_id,
                            shift_op: ShiftOp::Shl,
                            shift_amount: 1,
                        }],
                        constant: None,
                    }
                } else {
                    // Complex case: need a temp
                    let shift_temp = *next_temp;
                    *next_temp += 1;
                    constraints.push(Constraint::And {
                        a: carry_save.clone(),
                        b: Operand::from_constant(0xFFFFFFFF),
                        c: Operand::from_value(shift_temp),
                    });
                    Operand {
                        terms: vec![ShiftedValue {
                            value_id: shift_temp,
                            shift_op: ShiftOp::Shl,
                            shift_amount: 1,
                        }],
                        constant: None,
                    }
                };
                
                // Final sum with carry propagation
                let final_sum = partial_sum.xor(carry_shifted);
                
                constraints.push(Constraint::And {
                    a: final_sum,
                    b: Operand::from_constant(0xFFFFFFFF), // 32-bit mask
                    c: Operand::from_value(result),
                });
                
                return Some(constraints);
            }
        }
        None
    }
}

/// Build an operand from an expression node for carry chain
fn build_operand(expr: &Rc<ExprNode>) -> crate::constraints::Operand {
    use crate::constraints::Operand;
    
    match expr.as_ref() {
        ExprNode::Witness(id) => Operand::from_value(*id),
        ExprNode::Constant(val) => Operand::from_constant(*val),
        _ => {
            // For carry chain, we only handle witness and constant values
            // Complex expressions would need proper constraint generation
            Operand::from_value(0)
        }
    }
}

/// Detect chain of operations (additions) and extract the operands
fn detect_operation_chain(expr: &ExprNode) -> Option<Vec<Rc<ExprNode>>> {
    match expr {
        ExprNode::Add32(left, right) | ExprNode::Add64(left, right) => {
            // Recursively extract values from left side if it's also an addition
            let mut values = if let Some(left_chain) = detect_operation_chain(left) {
                left_chain
            } else {
                vec![Rc::clone(left)]
            };
            
            // Add the right value (recursively if it's also an addition chain)
            if let Some(right_chain) = detect_operation_chain(right) {
                values.extend(right_chain);
            } else {
                values.push(Rc::clone(right));
            }
            
            Some(values)
        }
        _ => None
    }
}

