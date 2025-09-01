//! Delayed binding constraint generation
//! 
//! This module implements constraint generation using delayed binding,
//! which delays creating temporary variables until absolutely necessary,
//! allowing better packing of expressions into constraints.
//!
//! Operandic operations (XOR, NOT, shifts) generate no constraints until 
//! materialized. Constraining operations (AND, MUL) generate constraints.

use crate::expr::ExprNode;
use crate::constraints::{Constraint, Operand, ShiftedValue, ShiftOp};
use std::rc::Rc;
use std::collections::HashMap;
use log::debug;

/// Builder for constraint generation with delayed binding
pub struct DelayedBindingBuilder {
    /// Generated constraints
    constraints: Vec<Constraint>,
    
    /// Next temporary variable ID
    next_temp: u32,
    
    /// Cache of already-computed expressions to enable sharing
    expr_cache: HashMap<*const ExprNode, Operand>,
    
    /// Optimization templates
    templates: Vec<Box<dyn crate::optimize::templates::ConstraintTemplate>>,
}

impl Default for DelayedBindingBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayedBindingBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            next_temp: 1000, // Start temp IDs at 1000
            expr_cache: HashMap::new(),
            templates: Vec::new(),
        }
    }
    
    /// Add a template for optimization
    pub fn add_template(&mut self, template: Box<dyn crate::optimize::templates::ConstraintTemplate>) {
        self.templates.push(template);
    }
    
    /// Generate constraints for an expression
    pub fn build(mut self, expr: &Rc<ExprNode>) -> Vec<Constraint> {
        // Build the expression - result is an operand
        let _result = self.build_expr(expr);
        
        // For now, if the expression is just XOR/NOT/shifts with no constraints,
        // we need to handle that case (user should use Equal to force evaluation)
        if self.constraints.is_empty() {
            debug!("Warning: Expression generates no constraints (pure operand operations)");
        }
        
        self.constraints
    }
    
    /// Build an expression, returning its operand representation
    fn build_expr(&mut self, expr: &Rc<ExprNode>) -> Operand {
        // Check cache first
        let expr_ptr = expr.as_ref() as *const ExprNode;
        if let Some(cached) = self.expr_cache.get(&expr_ptr) {
            return cached.clone();
        }
        
        // Check templates for multi-constraint patterns
        for template in &self.templates {
            if template.matches(expr.as_ref()) {
                if let Some(constraints) = template.generate(expr.as_ref(), &mut self.next_temp) {
                    // Template handled it, add constraints
                    self.constraints.extend(constraints);
                    // Return a temporary for the result (template should have allocated it)
                    return Operand::from_value(self.next_temp - 1);
                }
            }
        }
        
        let result = match expr.as_ref() {
            ExprNode::Witness(id) => Operand::from_value(*id),
            
            ExprNode::Constant(val) => Operand::from_constant(*val),
            
            // XOR operations build operands without constraints
            ExprNode::Xor(a, b) => {
                let a_op = self.build_expr(a);
                let b_op = self.build_expr(b);
                a_op.xor(b_op)
            }
            
            // NOT is XOR with all-ones
            ExprNode::Not(a) => {
                let a_op = self.build_expr(a);
                a_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF))
            }
            
            // Shifts are represented in operands
            ExprNode::Shl(a, amount) => self.build_shifted(a, ShiftOp::Shl, *amount),
            ExprNode::Shr(a, amount) => self.build_shifted(a, ShiftOp::Shr, *amount),
            ExprNode::Sar(a, amount) => self.build_shifted(a, ShiftOp::Sar, *amount),
            ExprNode::Rol(a, amount) => self.build_shifted(a, ShiftOp::Rol, *amount),
            ExprNode::Ror(a, amount) => self.build_shifted(a, ShiftOp::Ror, *amount),
            
            // AND requires a constraint, but check for XOR-absorbing pattern
            ExprNode::And(a, b) => self.build_and(a, b),
            
            // OR uses De Morgan's law: a | b = ~(~a & ~b)
            ExprNode::Or(a, b) => {
                let a_op = self.build_expr(a);
                let b_op = self.build_expr(b);
                
                // ~a & ~b
                let not_a = a_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF));
                let not_b = b_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF));
                
                let temp = self.next_temp;
                self.next_temp += 1;
                
                self.constraints.push(Constraint::And {
                    a: not_a,
                    b: not_b,
                    c: Operand::from_value(temp),
                });
                
                // ~(~a & ~b)
                Operand::from_value(temp).xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF))
            }
            
            // Arithmetic operations
            ExprNode::Add32(a, b) => self.build_add32(a, b),
            ExprNode::Add64(a, b) => self.build_add64(a, b),
            ExprNode::Sub32(a, b) => self.build_sub32(a, b),
            ExprNode::Sub64(a, b) => self.build_sub64(a, b),
            ExprNode::Mul32(a, b) => self.build_mul32(a, b),
            ExprNode::Mul64(a, b) => self.build_mul64(a, b),
            
            // Multiplexer
            ExprNode::Mux(cond, true_val, false_val) => {
                let cond_op = self.build_expr(cond);
                let true_op = self.build_expr(true_val);
                let false_op = self.build_expr(false_val);
                
                let result = self.next_temp;
                self.next_temp += 1;
                
                // result = cond & (true ⊕ false) ⊕ false
                self.constraints.push(Constraint::And {
                    a: cond_op,
                    b: true_op.xor(false_op.clone()),
                    c: Operand::from_value(result).xor(false_op),
                });
                
                Operand::from_value(result)
            }
            
            // Equality constraint
            ExprNode::Equal(a, b) => {
                // Check for patterns that can be optimized with delayed binding
                if let Some(optimized) = self.try_optimize_equal(a, b) {
                    return optimized;
                }
                
                // Default: generate equality constraint
                let a_op = self.build_expr(a);
                let b_op = self.build_expr(b);
                
                self.constraints.push(Constraint::And {
                    a: a_op.xor(b_op),
                    b: Operand::from_constant(0xFFFFFFFFFFFFFFFF),
                    c: Operand::from_constant(0),
                });
                
                Operand::from_constant(0)
            }
            
            // BlackBox nodes are treated as input values during constraint generation
            ExprNode::BlackBox { .. } => {
                // BlackBox is just an input value - allocate a temp ID for it
                let temp = self.next_temp;
                self.next_temp += 1;
                Operand::from_value(temp)
            }
        };
        
        // Cache the result
        self.expr_cache.insert(expr_ptr, result.clone());
        result
    }
    
    /// Build a shifted operand
    fn build_shifted(&mut self, expr: &Rc<ExprNode>, shift_op: ShiftOp, amount: u8) -> Operand {
        let base = self.build_expr(expr);
        
        // If base is a simple value, create shifted operand
        if base.terms.len() == 1 && base.constant.is_none() {
            let shifted_value = ShiftedValue {
                value_id: base.terms[0].value_id,
                shift_op,
                shift_amount: amount,
            };
            return Operand {
                terms: vec![shifted_value],
                constant: None,
            };
        }
        
        // For complex operands, we need a temp
        let temp = self.next_temp;
        self.next_temp += 1;
        
        self.constraints.push(Constraint::And {
            a: base,
            b: Operand::from_constant(0xFFFFFFFFFFFFFFFF),
            c: Operand::from_value(temp),
        });
        
        Operand {
            terms: vec![ShiftedValue {
                value_id: temp,
                shift_op,
                shift_amount: amount,
            }],
            constant: None,
        }
    }
    
    /// Build AND operation with delayed binding optimization
    fn build_and(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Operand {
        let a_op = self.build_expr(a);
        let b_op = self.build_expr(b);
        
        let result = self.next_temp;
        self.next_temp += 1;
        
        self.constraints.push(Constraint::And {
            a: a_op,
            b: b_op,
            c: Operand::from_value(result),
        });
        
        Operand::from_value(result)
    }
    
    /// Try to optimize Equal patterns using delayed binding
    fn try_optimize_equal(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Option<Operand> {
        // Pattern: witness = a ⊕ ((¬b) & c)
        // Can be encoded as single constraint: (b ⊕ 0xFF..) & c ⊕ (a ⊕ witness) = 0
        
        // Check if a is witness and b matches the pattern
        if let ExprNode::Witness(witness_id) = a.as_ref() {
            if let ExprNode::Xor(xor_a, and_part) = b.as_ref() {
                if let ExprNode::And(not_part, c) = and_part.as_ref() {
                    if let ExprNode::Not(not_b) = not_part.as_ref() {
                        // Found the pattern!
                        debug!("Delayed binding optimization: masked AND-XOR pattern");
                        
                        let a_op = self.build_expr(xor_a);
                        let b_op = self.build_expr(not_b);
                        let c_op = self.build_expr(c);
                        
                        self.constraints.push(Constraint::And {
                            a: b_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF)),
                            b: c_op,
                            c: a_op.xor(Operand::from_value(*witness_id)),
                        });
                        
                        return Some(Operand::from_value(*witness_id));
                    }
                }
            }
        }
        
        // Check reverse: a ⊕ ((¬b) & c) = witness
        if let ExprNode::Witness(witness_id) = b.as_ref() {
            if let ExprNode::Xor(xor_a, and_part) = a.as_ref() {
                if let ExprNode::And(not_part, c) = and_part.as_ref() {
                    if let ExprNode::Not(not_b) = not_part.as_ref() {
                        debug!("Delayed binding optimization: masked AND-XOR pattern (reversed)");
                        
                        let a_op = self.build_expr(xor_a);
                        let b_op = self.build_expr(not_b);
                        let c_op = self.build_expr(c);
                        
                        self.constraints.push(Constraint::And {
                            a: b_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF)),
                            b: c_op,
                            c: a_op.xor(Operand::from_value(*witness_id)),
                        });
                        
                        return Some(Operand::from_value(*witness_id));
                    }
                }
            }
        }
        
        None
    }
    
    /// Build 32-bit addition
    fn build_add32(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Operand {
        let a_op = self.build_expr(a);
        let b_op = self.build_expr(b);
        
        let cout = self.next_temp;
        self.next_temp += 1;
        let result = self.next_temp;
        self.next_temp += 1;
        
        // Carry propagation
        let cout_shifted = Operand {
            terms: vec![ShiftedValue {
                value_id: cout,
                shift_op: ShiftOp::Shl,
                shift_amount: 1,
            }],
            constant: None,
        };
        
        self.constraints.push(Constraint::And {
            a: a_op.clone().xor(cout_shifted.clone()),
            b: b_op.clone().xor(cout_shifted.clone()),
            c: Operand::from_value(cout).xor(cout_shifted.clone()),
        });
        
        // Result with 32-bit masking
        self.constraints.push(Constraint::And {
            a: a_op.xor(b_op).xor(cout_shifted),
            b: Operand::from_constant(0xFFFFFFFF),
            c: Operand::from_value(result),
        });
        
        Operand::from_value(result)
    }
    
    /// Build 64-bit addition
    fn build_add64(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Operand {
        let a_op = self.build_expr(a);
        let b_op = self.build_expr(b);
        
        let cout = self.next_temp;
        self.next_temp += 1;
        let result = self.next_temp;
        self.next_temp += 1;
        
        // Carry propagation
        let cout_shifted = Operand {
            terms: vec![ShiftedValue {
                value_id: cout,
                shift_op: ShiftOp::Shl,
                shift_amount: 1,
            }],
            constant: None,
        };
        
        self.constraints.push(Constraint::And {
            a: a_op.clone().xor(cout_shifted.clone()),
            b: b_op.clone().xor(cout_shifted.clone()),
            c: Operand::from_value(cout).xor(cout_shifted.clone()),
        });
        
        // Result
        self.constraints.push(Constraint::And {
            a: a_op.xor(b_op).xor(cout_shifted),
            b: Operand::from_constant(0xFFFFFFFFFFFFFFFF),
            c: Operand::from_value(result),
        });
        
        Operand::from_value(result)
    }
    
    /// Build 32-bit subtraction
    fn build_sub32(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Operand {
        let a_op = self.build_expr(a);
        let b_op = self.build_expr(b);
        
        let bout = self.next_temp;
        self.next_temp += 1;
        let result = self.next_temp;
        self.next_temp += 1;
        
        // Borrow propagation (similar to carry but for subtraction)
        let bout_shifted = Operand {
            terms: vec![ShiftedValue {
                value_id: bout,
                shift_op: ShiftOp::Shl,
                shift_amount: 1,
            }],
            constant: None,
        };
        
        // For subtraction: a - b = a + (~b) + 1
        let not_b = b_op.xor(Operand::from_constant(0xFFFFFFFF));
        
        self.constraints.push(Constraint::And {
            a: a_op.clone().xor(bout_shifted.clone()),
            b: not_b.clone().xor(bout_shifted.clone()),
            c: Operand::from_value(bout).xor(bout_shifted.clone()),
        });
        
        // Result with 32-bit masking
        self.constraints.push(Constraint::And {
            a: a_op.xor(not_b).xor(bout_shifted).xor(Operand::from_constant(1)),
            b: Operand::from_constant(0xFFFFFFFF),
            c: Operand::from_value(result),
        });
        
        Operand::from_value(result)
    }
    
    /// Build 64-bit subtraction
    fn build_sub64(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Operand {
        let a_op = self.build_expr(a);
        let b_op = self.build_expr(b);
        
        let bout = self.next_temp;
        self.next_temp += 1;
        let result = self.next_temp;
        self.next_temp += 1;
        
        // Borrow propagation
        let bout_shifted = Operand {
            terms: vec![ShiftedValue {
                value_id: bout,
                shift_op: ShiftOp::Shl,
                shift_amount: 1,
            }],
            constant: None,
        };
        
        // For subtraction: a - b = a + (~b) + 1
        let not_b = b_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF));
        
        self.constraints.push(Constraint::And {
            a: a_op.clone().xor(bout_shifted.clone()),
            b: not_b.clone().xor(bout_shifted.clone()),
            c: Operand::from_value(bout).xor(bout_shifted.clone()),
        });
        
        // Result
        self.constraints.push(Constraint::And {
            a: a_op.xor(not_b).xor(bout_shifted).xor(Operand::from_constant(1)),
            b: Operand::from_constant(0xFFFFFFFFFFFFFFFF),
            c: Operand::from_value(result),
        });
        
        Operand::from_value(result)
    }
    
    /// Build 32-bit multiplication
    fn build_mul32(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Operand {
        let a_op = self.build_expr(a);
        let b_op = self.build_expr(b);
        
        let hi = self.next_temp;
        self.next_temp += 1;
        let lo = self.next_temp;
        self.next_temp += 1;
        
        self.constraints.push(Constraint::Mul {
            a: a_op,
            b: b_op,
            hi,
            lo,
        });
        
        // For 32-bit mul, we typically only care about the low part
        Operand::from_value(lo)
    }
    
    /// Build 64-bit multiplication
    fn build_mul64(&mut self, a: &Rc<ExprNode>, b: &Rc<ExprNode>) -> Operand {
        let a_op = self.build_expr(a);
        let b_op = self.build_expr(b);
        
        let hi = self.next_temp;
        self.next_temp += 1;
        let lo = self.next_temp;
        self.next_temp += 1;
        
        self.constraints.push(Constraint::Mul {
            a: a_op,
            b: b_op,
            hi,
            lo,
        });
        
        Operand::from_value(lo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{val, and, xor, not, eq};
    use crate::types::Field64;
    
    #[test]
    fn test_xor_chain_no_constraints() {
        // Pure XOR chain should generate no constraints
        let a = val::<Field64>(0);
        let b = val::<Field64>(1);
        let c = val::<Field64>(2);
        
        let expr = xor(&xor(&a, &b), &c);
        
        let builder = DelayedBindingBuilder::new();
        let constraints = builder.build(&expr.inner);
        
        assert_eq!(constraints.len(), 0, "XOR chain should generate no constraints");
    }
    
    #[test]
    fn test_and_generates_constraint() {
        let a = val::<Field64>(0);
        let b = val::<Field64>(1);
        
        let expr = and(&a, &b);
        
        let builder = DelayedBindingBuilder::new();
        let constraints = builder.build(&expr.inner);
        
        assert_eq!(constraints.len(), 1, "AND should generate 1 constraint");
        assert!(matches!(constraints[0], Constraint::And { .. }));
    }
    
    #[test]
    fn test_masked_and_xor_optimization() {
        let a = val::<Field64>(0);
        let b = val::<Field64>(1);
        let c = val::<Field64>(2);
        let result = val::<Field64>(3);
        
        // Pattern: result = a ⊕ ((¬b) & c)
        let pattern = xor(&a, &and(&not(&b), &c));
        let expr = eq(&result, &pattern);
        
        let builder = DelayedBindingBuilder::new();
        let constraints = builder.build(&expr.inner);
        
        // With optimization, should generate just 1 constraint
        assert_eq!(constraints.len(), 1, "Masked AND-XOR pattern should generate 1 constraint");
    }
}