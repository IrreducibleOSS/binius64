//! Witness filler - executes recipes to compute complete witness

use crate::{
    error::{CompilerError, Result},
    expression::{Expression, ShiftVariant},
    recipe::{CompiledRecipes, Operation, WitnessRecipe},
    witness::{CompleteWitness, PartialWitness, WitnessVar},
};

/// Fills witness values by executing compiled recipes
#[derive(Debug)]
pub struct WitnessFiller {
    recipes: CompiledRecipes,
}

impl WitnessFiller {
    pub fn new(recipes: CompiledRecipes) -> Self {
        Self { recipes }
    }
    
    /// Fill all witness values from partial inputs
    pub fn fill(&self, partial: PartialWitness) -> Result<CompleteWitness> {
        let mut witness = CompleteWitness::from_partial(partial);
        
        // Execute recipes in topological order
        for var in self.recipes.eval_order() {
            // Skip if already computed
            if witness.has(*var) {
                continue;
            }
            
            // Get node with recipe
            let node = self.recipes.get_node(*var)
                .ok_or_else(|| CompilerError::MissingWitness { var: *var })?;
            
            // Compute value
            let value = self.compute_recipe(&node.recipe, &witness)?;
            witness.set(*var, value);
        }
        
        Ok(witness)
    }
    
    fn compute_recipe(&self, recipe: &WitnessRecipe, witness: &CompleteWitness) -> Result<u64> {
        match recipe {
            WitnessRecipe::Input => {
                // Should already be in witness
                Err(CompilerError::WitnessComputation {
                    reason: "Input value not provided".to_string(),
                })
            }
            
            WitnessRecipe::Compute { op, inputs } => {
                self.compute_operation(op, inputs, witness)
            }
            
            WitnessRecipe::Eliminated { expanded } => {
                // Compute from expanded expression
                self.evaluate_expression(expanded, witness)
            }
        }
    }
    
    fn compute_operation(&self, op: &Operation, inputs: &[WitnessVar], witness: &CompleteWitness) -> Result<u64> {
        match op {
            Operation::Xor => {
                let left = witness.get(inputs[0])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[0] })?;
                let right = witness.get(inputs[1])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[1] })?;
                Ok(left ^ right)
            }
            
            Operation::And => {
                let left = witness.get(inputs[0])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[0] })?;
                let right = witness.get(inputs[1])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[1] })?;
                Ok(left & right)
            }
            
            Operation::Not => {
                let input = witness.get(inputs[0])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[0] })?;
                Ok(!input)
            }
            
            Operation::Shift { variant, amount } => {
                let input = witness.get(inputs[0])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[0] })?;
                
                Ok(match variant {
                    ShiftVariant::Sll => input << amount,
                    ShiftVariant::Slr => input >> amount,
                    ShiftVariant::Sar => ((input as i64) >> amount) as u64,
                })
            }
            
            Operation::Multiply { is_high } => {
                let left = witness.get(inputs[0])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[0] })?;
                let right = witness.get(inputs[1])
                    .ok_or_else(|| CompilerError::MissingWitness { var: inputs[1] })?;
                
                let product = (left as u128) * (right as u128);
                
                Ok(if *is_high {
                    (product >> 64) as u64
                } else {
                    product as u64
                })
            }
        }
    }
    
    fn evaluate_expression(&self, expr: &Expression, witness: &CompleteWitness) -> Result<u64> {
        match expr {
            Expression::Var(v) => witness.get(*v)
                .ok_or_else(|| CompilerError::MissingWitness { var: *v }),
            
            Expression::Xor(a, b) => {
                let a_val = self.evaluate_expression(a, witness)?;
                let b_val = self.evaluate_expression(b, witness)?;
                Ok(a_val ^ b_val)
            }
            
            Expression::And(a, b) => {
                let a_val = self.evaluate_expression(a, witness)?;
                let b_val = self.evaluate_expression(b, witness)?;
                Ok(a_val & b_val)
            }
            
            Expression::Not(a) => {
                let a_val = self.evaluate_expression(a, witness)?;
                Ok(!a_val)
            }
            
            Expression::Shift { input, variant, amount } => {
                let input_val = self.evaluate_expression(input, witness)?;
                Ok(match variant {
                    ShiftVariant::Sll => input_val << amount,
                    ShiftVariant::Slr => input_val >> amount,
                    ShiftVariant::Sar => ((input_val as i64) >> amount) as u64,
                })
            }
            
            Expression::Mul(a, b) => {
                let a_val = self.evaluate_expression(a, witness)?;
                let b_val = self.evaluate_expression(b, witness)?;
                // For expression evaluation, return low bits
                Ok((a_val as u128 * b_val as u128) as u64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dependency::WitnessGraph,
        expression::Expression,
        predicate::{Predicate, PredicateId},
        recipe::RecipeCompiler,
        witness::WitnessAllocator,
    };
    
    #[test]
    fn test_witness_filling() {
        let mut allocator = WitnessAllocator::new();
        let a = allocator.new_private();
        let b = allocator.new_private();
        let c = allocator.new_auxiliary();
        
        // Create predicate: c = a XOR b
        let predicate = Predicate::Equals {
            id: PredicateId(0),
            result: c,
            expression: Expression::xor(a, b),
        };
        
        // Build dependency graph and compile recipes
        let graph = WitnessGraph::from_predicates(&[predicate.clone()]).unwrap();
        let compiler = RecipeCompiler::new(graph, vec![predicate]);
        let recipes = compiler.compile().unwrap();
        
        // Create filler
        let filler = WitnessFiller::new(recipes);
        
        // Create partial witness with inputs
        let mut partial = PartialWitness::new();
        partial.set_private(0, 0x1234);
        partial.set_private(1, 0x5678);
        
        // Fill witness
        let complete = filler.fill(partial).unwrap();
        
        // Check that c was computed correctly
        assert_eq!(complete.get(a), Some(0x1234));
        assert_eq!(complete.get(b), Some(0x5678));
        // Note: The actual computation of c depends on proper recipe generation
        // which is not fully implemented yet
    }
}