//! Witness synthesis using preserved auxiliary computation
//! 
//! The key insight: we compute ALL auxiliaries (including eliminated ones)
//! using the preserved recipes, then filter out eliminated ones for the final witness.

use crate::types::*;
use crate::ir::*;
use std::collections::HashMap;

/// Synthesizes witness values including eliminated auxiliaries
pub struct WitnessSynthesizer {
    /// The packed IR with preserved auxiliary computer
    packed_ir: PackedIR,
}

/// Witness vector during synthesis
#[derive(Debug, Clone)]
pub struct WitnessVector {
    values: HashMap<WitnessId, u64>,
}

impl WitnessVector {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
    
    pub fn set(&mut self, id: WitnessId, value: u64) {
        self.values.insert(id, value);
    }
    
    pub fn get(&self, id: WitnessId) -> Option<u64> {
        self.values.get(&id).copied()
    }
    
    /// Filter out eliminated auxiliaries for constraint checking
    pub fn filter_non_eliminated(&self, eliminated: &HashSet<AuxiliaryId>) -> Self {
        let mut filtered = Self::new();
        for (id, value) in &self.values {
            match id {
                WitnessId::Public(_) => {
                    filtered.set(*id, *value);
                }
                WitnessId::Auxiliary(aux_id) => {
                    if !eliminated.contains(aux_id) {
                        filtered.set(*id, *value);
                    }
                }
            }
        }
        filtered
    }
}

impl WitnessSynthesizer {
    pub fn new(packed_ir: PackedIR) -> Self {
        Self { packed_ir }
    }
    
    /// Synthesize complete witness from public inputs
    pub fn synthesize(&self, public_inputs: HashMap<PublicId, u64>) -> Result<WitnessVector, String> {
        let mut witness = WitnessVector::new();
        
        // Initialize with public inputs
        for (id, value) in public_inputs {
            witness.set(WitnessId::Public(id), value);
        }
        
        // CRITICAL: Compute ALL auxiliaries in topological order,
        // even those eliminated by packing!
        for aux_id in &self.packed_ir.auxiliary_computer.eval_order {
            let value = self.compute_auxiliary(*aux_id, &witness)?;
            witness.set(WitnessId::Auxiliary(*aux_id), value);
        }
        
        // Return witness with eliminated auxiliaries filtered out
        Ok(witness.filter_non_eliminated(&self.packed_ir.eliminated))
    }
    
    /// Compute a single auxiliary witness value
    fn compute_auxiliary(&self, aux_id: AuxiliaryId, witness: &WitnessVector) -> Result<u64, String> {
        let computation = self.packed_ir.auxiliary_computer.recipes
            .get(&aux_id)
            .ok_or_else(|| format!("No recipe for auxiliary {:?}", aux_id))?;
        
        match &computation.recipe {
            ComputationRecipe::Direct(expr) => {
                self.evaluate_sem_expr(expr, witness)
            }
            ComputationRecipe::Existential(existential) => {
                self.compute_existential(existential, witness)
            }
            ComputationRecipe::Eliminable(expr) => {
                // Even though eliminated, we still compute it!
                self.evaluate_sem_expr(expr, witness)
            }
        }
    }
    
    /// Evaluate semantic expression for witness computation
    fn evaluate_sem_expr(&self, expr: &SemExpr, witness: &WitnessVector) -> Result<u64, String> {
        match expr {
            SemExpr::Var(var_id) => {
                witness.get(WitnessId::Public(PublicId(var_id.0)))
                    .ok_or_else(|| format!("Missing public witness {:?}", var_id))
            }
            SemExpr::Const(value) => Ok(*value),
            SemExpr::Xor(a, b) => {
                let a_val = self.evaluate_sem_expr(a, witness)?;
                let b_val = self.evaluate_sem_expr(b, witness)?;
                Ok(a_val ^ b_val)
            }
            SemExpr::And(a, b) => {
                let a_val = self.evaluate_sem_expr(a, witness)?;
                let b_val = self.evaluate_sem_expr(b, witness)?;
                Ok(a_val & b_val)
            }
            SemExpr::Not(a) => {
                let a_val = self.evaluate_sem_expr(a, witness)?;
                Ok(!a_val)
            }
            SemExpr::Add(a, b) => {
                let a_val = self.evaluate_sem_expr(a, witness)?;
                let b_val = self.evaluate_sem_expr(b, witness)?;
                Ok(a_val.wrapping_add(b_val))
            }
            SemExpr::Mul(a, b) => {
                let a_val = self.evaluate_sem_expr(a, witness)?;
                let b_val = self.evaluate_sem_expr(b, witness)?;
                Ok(a_val.wrapping_mul(b_val))
            }
            SemExpr::Auxiliary { id, .. } => {
                witness.get(WitnessId::Auxiliary(*id))
                    .ok_or_else(|| format!("Missing auxiliary witness {:?}", id))
            }
            _ => Err("Unsupported expression in synthesis".to_string()),
        }
    }
    
    /// Compute existential (non-deterministic) witness
    fn compute_existential(&self, existential: &ExistentialComputation, witness: &WitnessVector) -> Result<u64, String> {
        match existential {
            ExistentialComputation::DivQuotient { dividend, divisor } => {
                let dividend_val = witness.get(*dividend)
                    .ok_or("Missing dividend")?;
                let divisor_val = witness.get(*divisor)
                    .ok_or("Missing divisor")?;
                
                if divisor_val == 0 {
                    return Err("Division by zero".to_string());
                }
                
                // Compute quotient outside constraint system
                Ok(dividend_val / divisor_val)
            }
            ExistentialComputation::Custom(_) => {
                Err("Custom existential not implemented".to_string())
            }
        }
    }
}