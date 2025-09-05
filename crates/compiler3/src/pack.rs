//! Operand packing with auxiliary preservation
//! 
//! The key innovation: we preserve auxiliary computation recipes even as we
//! eliminate the auxiliaries from constraints through packing.

use crate::types::*;
use crate::ir::*;
use std::collections::{HashMap, HashSet};

/// Packs constraints while preserving auxiliary computation
pub struct Packer {
    /// Cost model for packing decisions
    cost_model: CostModel,
}

#[derive(Debug, Clone)]
pub struct CostModel {
    pub and_cost: f64,      // 1.0 (baseline)
    pub mul_cost: f64,      // 200.0 (expensive)
    pub operand_term_cost: f64,  // 0.0 (free within operand)
}

impl Default for CostModel {
    fn default() -> Self {
        Self {
            and_cost: 1.0,
            mul_cost: 200.0,
            operand_term_cost: 0.0,
        }
    }
}

impl Packer {
    pub fn new() -> Self {
        Self {
            cost_model: CostModel::default(),
        }
    }
    
    /// Pack constraints while preserving auxiliary computation
    pub fn pack(self, cir: ConstraintIR) -> Result<PackedIR, String> {
        // CRITICAL: Preserve auxiliary computer BEFORE packing
        let auxiliary_computer = AuxiliaryComputer::from_constraint_ir(&cir);
        
        let mut packed_constraints = Vec::new();
        let mut eliminated = HashSet::new();
        let mut remaining_constraints = cir.constraints.clone();
        
        // Simple packing: look for XOR chains to consolidate
        while !remaining_constraints.is_empty() {
            if let Some(packed) = self.try_pack_xor_chain(&mut remaining_constraints, &mut eliminated) {
                packed_constraints.push(packed);
            } else {
                // Can't pack, convert to Binius constraint directly
                let constraint = remaining_constraints.remove(0);
                packed_constraints.push(self.basic_to_binius(constraint)?);
            }
        }
        
        Ok(PackedIR {
            constraints: packed_constraints,
            eliminated,
            auxiliary_computer, // Preserved from BEFORE packing!
        })
    }
    
    /// Try to pack a chain of XOR operations
    fn try_pack_xor_chain(
        &self,
        constraints: &mut Vec<BasicConstraint>,
        eliminated: &mut HashSet<AuxiliaryId>,
    ) -> Option<BiniusConstraint> {
        // Look for pattern: t = a XOR b, u = t XOR c, ...
        // Can pack into single operand: a XOR b XOR c
        
        for i in 0..constraints.len() {
            if let BasicConstraint::Equals { result, expr: ConstraintExpr::Xor(_, _) } = &constraints[i] {
                // Check if this result is used in another XOR
                for j in 0..constraints.len() {
                    if i != j {
                        if let BasicConstraint::Equals { expr, .. } = &constraints[j] {
                            if self.expr_uses_witness(expr, *result) {
                                // Found a chain! Pack it
                                // Mark intermediate as eliminated
                                if let WitnessId::Auxiliary(aux_id) = result {
                                    eliminated.insert(*aux_id);
                                }
                                
                                // For now, just remove the first constraint
                                // In real implementation, would merge operands
                                constraints.remove(i);
                                return None; // Continue packing
                            }
                        }
                    }
                }
            }
        }
        
        None
    }
    
    /// Check if expression uses a witness
    fn expr_uses_witness(&self, expr: &ConstraintExpr, witness: WitnessId) -> bool {
        match expr {
            ConstraintExpr::Witness(w) => *w == witness,
            ConstraintExpr::Xor(a, b) | ConstraintExpr::And(a, b) => {
                self.expr_uses_witness(a, witness) || self.expr_uses_witness(b, witness)
            }
            ConstraintExpr::Not(a) | ConstraintExpr::Shift { input: a, .. } => {
                self.expr_uses_witness(a, witness)
            }
        }
    }
    
    /// Convert basic constraint to Binius constraint
    fn basic_to_binius(&self, constraint: BasicConstraint) -> Result<BiniusConstraint, String> {
        match constraint {
            BasicConstraint::Equals { result, expr } => {
                match expr {
                    ConstraintExpr::And(a_expr, b_expr) => {
                        // Convert to AND constraint: (A) & (B) ⊕ (C) = 0
                        let a = self.expr_to_operand(*a_expr)?;
                        let b = self.expr_to_operand(*b_expr)?;
                        let c = self.witness_to_operand(result);
                        
                        Ok(BiniusConstraint::And { a, b, c })
                    }
                    _ => {
                        // For XOR and other free operations, create trivial AND constraint
                        // (expr) & (0xFF..FF) ⊕ (result) = 0
                        let a = self.expr_to_operand(expr)?;
                        let b = Operand {
                            terms: vec![],
                            constant: Some(u64::MAX), // All ones
                        };
                        let c = self.witness_to_operand(result);
                        
                        Ok(BiniusConstraint::And { a, b, c })
                    }
                }
            }
            BasicConstraint::Multiply { left, right, hi, lo } => {
                Ok(BiniusConstraint::Mul {
                    a: self.witness_to_operand(left),
                    b: self.witness_to_operand(right),
                    hi,
                    lo,
                })
            }
        }
    }
    
    /// Convert constraint expression to operand
    fn expr_to_operand(&self, expr: ConstraintExpr) -> Result<Operand, String> {
        match expr {
            ConstraintExpr::Witness(w) => Ok(self.witness_to_operand(w)),
            ConstraintExpr::Xor(a, b) => {
                // XOR becomes sum of terms in operand
                let mut a_op = self.expr_to_operand(*a)?;
                let b_op = self.expr_to_operand(*b)?;
                a_op.terms.extend(b_op.terms);
                if let Some(b_const) = b_op.constant {
                    a_op.constant = Some(a_op.constant.unwrap_or(0) ^ b_const);
                }
                Ok(a_op)
            }
            ConstraintExpr::Shift { input, op, amount } => {
                let mut base_op = self.expr_to_operand(*input)?;
                // Apply shift to all terms
                for term in &mut base_op.terms {
                    term.shift = Some((op, amount));
                }
                Ok(base_op)
            }
            _ => Err("Cannot convert expression to operand".to_string()),
        }
    }
    
    /// Convert witness to simple operand
    fn witness_to_operand(&self, witness: WitnessId) -> Operand {
        Operand {
            terms: vec![Term {
                witness,
                shift: None,
            }],
            constant: None,
        }
    }
}

impl CostModel {
    /// Evaluate the benefit of packing
    pub fn evaluate_packing(&self, before: &[BasicConstraint], after: &BiniusConstraint) -> f64 {
        let before_cost: f64 = before.iter().map(|c| self.constraint_cost(c)).sum();
        let after_cost = self.binius_constraint_cost(after);
        before_cost - after_cost // Positive means beneficial
    }
    
    fn constraint_cost(&self, constraint: &BasicConstraint) -> f64 {
        match constraint {
            BasicConstraint::Equals { expr, .. } => {
                match expr {
                    ConstraintExpr::And(_, _) => self.and_cost,
                    _ => 0.1, // Very cheap for XOR/NOT/shifts
                }
            }
            BasicConstraint::Multiply { .. } => self.mul_cost,
        }
    }
    
    fn binius_constraint_cost(&self, constraint: &BiniusConstraint) -> f64 {
        match constraint {
            BiniusConstraint::And { .. } => self.and_cost,
            BiniusConstraint::Mul { .. } => self.mul_cost,
        }
    }
}