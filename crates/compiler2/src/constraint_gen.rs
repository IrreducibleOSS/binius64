//! Constraint generation from predicates

use crate::{
    expression::Expression,
    predicate::Predicate,
    witness::WitnessVar,
    error::Result,
};
use binius_core::constraint_system::{
    AndConstraint, MulConstraint, ShiftedValueIndex, ValueIndex, ShiftVariant,
};
use std::collections::HashMap;

/// Convert our ShiftVariant to core ShiftVariant
fn convert_shift_variant(variant: crate::expression::ShiftVariant) -> ShiftVariant {
    match variant {
        crate::expression::ShiftVariant::Sll => ShiftVariant::Sll,
        crate::expression::ShiftVariant::Slr => ShiftVariant::Slr,
        crate::expression::ShiftVariant::Sar => ShiftVariant::Sar,
    }
}

/// Generates constraints from predicates
pub struct ConstraintGenerator {
    /// Mapping from witness variables to ValueIndex
    witness_to_value: HashMap<WitnessVar, ValueIndex>,
    /// Next available ValueIndex
    next_value_index: u32,
    /// Generated AND constraints
    and_constraints: Vec<AndConstraint>,
    /// Generated MUL constraints
    mul_constraints: Vec<MulConstraint>,
}

impl ConstraintGenerator {
    pub fn new() -> Self {
        Self {
            witness_to_value: HashMap::new(),
            next_value_index: 0,
            and_constraints: Vec::new(),
            mul_constraints: Vec::new(),
        }
    }
    
    /// Generate constraints from predicates
    pub fn generate(&mut self, predicates: &[Predicate]) -> Result<()> {
        for predicate in predicates {
            self.generate_predicate(predicate)?;
        }
        Ok(())
    }
    
    fn generate_predicate(&mut self, predicate: &Predicate) -> Result<()> {
        match predicate {
            Predicate::Equals { result, expression, .. } => {
                // Generate constraint for result = expression
                match expression {
                    Expression::BinaryOp { op: crate::recipe::BinaryOp::And, left, right } => {
                        // Generate AND constraint
                        let a_operand = vec![self.witness_to_shifted(*left)];
                        let b_operand = vec![self.witness_to_shifted(*right)];
                        let c_operand = vec![self.witness_to_shifted(*result)];
                        
                        self.and_constraints.push(AndConstraint {
                            a: a_operand,
                            b: b_operand,
                            c: c_operand,
                        });
                    }
                    _ => {
                        // For XOR, NOT, SHIFT - these are "free" operations
                        // In unpacked mode, we still need to generate constraints
                        // to establish the equality relationship
                        
                        // For now, generate an AND constraint with identity:
                        // result = expression is encoded as:
                        // expression AND 1 = result (where 1 is all-ones constant)
                        let expr_operand = self.expression_to_operand(expression)?;
                        let ones_operand = vec![ShiftedValueIndex {
                            value_index: ValueIndex(u32::MAX), // Constant all-ones
                            shift_variant: ShiftVariant::Sll,
                            amount: 0,
                        }];
                        let result_operand = vec![self.witness_to_shifted(*result)];
                        
                        self.and_constraints.push(AndConstraint {
                            a: expr_operand,
                            b: ones_operand,
                            c: result_operand,
                        });
                    }
                }
            }
            Predicate::Multiply { hi, lo, a, b, .. } => {
                // Generate MUL constraint
                let a_operand = self.expression_to_operand(a)?;
                let b_operand = self.expression_to_operand(b)?;
                let hi_operand = vec![self.witness_to_shifted(*hi)];
                let lo_operand = vec![self.witness_to_shifted(*lo)];
                
                self.mul_constraints.push(MulConstraint {
                    a: a_operand,
                    b: b_operand,
                    hi: hi_operand,
                    lo: lo_operand,
                });
            }
        }
        Ok(())
    }
    
    /// Convert expression to operand (list of shifted value indices) 
    /// For recipe-based expressions, this handles the operand creation
    fn expression_to_operand(&mut self, expr: &Expression) -> Result<Vec<ShiftedValueIndex>> {
        match expr {
            Expression::Var(v) => {
                Ok(vec![self.witness_to_shifted(*v)])
            }
            Expression::Constant { value: _ } => {
                // Constants become special value indices
                Ok(vec![ShiftedValueIndex {
                    value_index: ValueIndex(u32::MAX), // Special constant marker
                    shift_variant: binius_core::constraint_system::ShiftVariant::Sll,
                    amount: 0,
                }])
            }
            Expression::BinaryOp { op: crate::recipe::BinaryOp::Xor, left, right } => {
                // XOR creates operand from both sides
                let mut operand = vec![self.witness_to_shifted(*left)];
                operand.push(self.witness_to_shifted(*right));
                Ok(operand)
            }
            Expression::BinaryOp { op: crate::recipe::BinaryOp::And, left: _, right: _ } => {
                // AND should be handled at predicate level, not as sub-expressions
                Err(crate::error::CompilerError::RecipeCompilation {
                    reason: "AND should not appear as sub-expressions".to_string(),
                })
            }
            Expression::UnaryOp { op: crate::recipe::UnaryOp::Not, input } => {
                // NOT is XOR with all-ones constant
                let mut operand = vec![self.witness_to_shifted(*input)];
                operand.push(ShiftedValueIndex {
                    value_index: ValueIndex(u32::MAX), // Constant all-ones
                    shift_variant: binius_core::constraint_system::ShiftVariant::Sll,
                    amount: 0,
                });
                Ok(operand)
            }
            Expression::Shift { input, variant, amount } => {
                // Create shifted operand directly
                let core_variant = convert_shift_variant(*variant);
                Ok(vec![ShiftedValueIndex {
                    value_index: self.witness_to_shifted(*input).value_index,
                    shift_variant: core_variant,
                    amount: *amount as usize,
                }])
            }
            Expression::Multiply { left: _, right: _, is_high: _ } => {
                // Multiply should be handled at predicate level, not as sub-expressions
                Err(crate::error::CompilerError::RecipeCompilation {
                    reason: "MUL should not appear as sub-expressions".to_string(),
                })
            }
        }
    }
    
    /// Convert witness variable to shifted value index
    fn witness_to_shifted(&mut self, witness: WitnessVar) -> ShiftedValueIndex {
        let value_index = self.get_or_create_value_index(witness);
        ShiftedValueIndex {
            value_index,
            shift_variant: ShiftVariant::Sll,
            amount: 0,
        }
    }
    
    /// Get or create ValueIndex for a witness variable
    fn get_or_create_value_index(&mut self, witness: WitnessVar) -> ValueIndex {
        match witness {
            WitnessVar::Constant { value } if value == u64::MAX => {
                // Special case: all-ones constant
                ValueIndex(u32::MAX)
            }
            WitnessVar::Constant { value } if value == 0 => {
                // Special case: zero constant
                // We could use a special index, for now use regular allocation
                *self.witness_to_value.entry(witness).or_insert_with(|| {
                    let idx = ValueIndex(self.next_value_index);
                    self.next_value_index += 1;
                    idx
                })
            }
            _ => {
                *self.witness_to_value.entry(witness).or_insert_with(|| {
                    let idx = ValueIndex(self.next_value_index);
                    self.next_value_index += 1;
                    idx
                })
            }
        }
    }
    
    /// Get the number of witnesses used
    pub fn num_witnesses(&self) -> usize {
        self.next_value_index as usize
    }
    
    /// Consume the generator and return the constraints
    pub fn into_constraints(self) -> (Vec<AndConstraint>, Vec<MulConstraint>) {
        (self.and_constraints, self.mul_constraints)
    }
}