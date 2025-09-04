//! Packing engine - optimizes constraints while preserving witness computability

use std::collections::HashMap;

use crate::{
    dependency::WitnessGraph,
    error::Result,
    predicate::{Predicate, PredicateId},
    witness::WitnessVar,
};

/// Decision about whether to pack a predicate
#[derive(Debug, Clone)]
pub struct PackingDecision {
    pub predicate_id: PredicateId,
    pub should_pack: bool,
    pub reason: PackingReason,
}

/// Reason for packing decision
#[derive(Debug, Clone)]
pub enum PackingReason {
    /// Result is used by other predicates
    ResultUsedElsewhere,
    
    /// Result is a circuit output
    ResultIsOutput,
    
    /// Free operation that can be packed
    FreeOperation,
    
    /// Constraint operation that cannot be packed
    ConstraintOperation,
}

/// Engine that analyzes and performs predicate packing
pub struct PackingEngine {
    graph: WitnessGraph,
    predicates: Vec<Predicate>,
    decisions: HashMap<PredicateId, PackingDecision>,
    enable_packing: bool,
}

impl PackingEngine {
    pub fn new(graph: WitnessGraph, predicates: Vec<Predicate>, enable_packing: bool) -> Self {
        Self {
            graph,
            predicates,
            decisions: HashMap::new(),
            enable_packing,
        }
    }
    
    /// Analyze all predicates and decide which to pack
    pub fn analyze(&mut self) -> Result<()> {
        for predicate in &self.predicates {
            let decision = self.analyze_predicate(predicate)?;
            self.decisions.insert(predicate.id(), decision);
        }
        Ok(())
    }
    
    fn analyze_predicate(&self, predicate: &Predicate) -> Result<PackingDecision> {
        let id = predicate.id();
        
        // If packing is disabled, don't pack anything
        if !self.enable_packing {
            return Ok(PackingDecision {
                predicate_id: id,
                should_pack: false,
                reason: PackingReason::ConstraintOperation, // Use as generic "don't pack" reason
            });
        }
        
        // Check if this is a constraint operation (AND, MUL)
        if !predicate.can_pack() {
            return Ok(PackingDecision {
                predicate_id: id,
                should_pack: false,
                reason: PackingReason::ConstraintOperation,
            });
        }
        
        // Check if result is used elsewhere
        for result_var in predicate.result_vars() {
            if self.graph.is_output(result_var) {
                return Ok(PackingDecision {
                    predicate_id: id,
                    should_pack: false,
                    reason: PackingReason::ResultIsOutput,
                });
            }
            
            if self.graph.is_shared(result_var) {
                return Ok(PackingDecision {
                    predicate_id: id,
                    should_pack: false,
                    reason: PackingReason::ResultUsedElsewhere,
                });
            }
        }
        
        // Can pack this predicate
        Ok(PackingDecision {
            predicate_id: id,
            should_pack: true,
            reason: PackingReason::FreeOperation,
        })
    }
    
    /// Check if a witness can be eliminated
    pub fn can_eliminate_witness(&self, var: WitnessVar) -> bool {
        !self.graph.is_shared(var) && !self.graph.is_output(var)
    }
    
    /// Apply packing decisions and generate optimized constraints
    pub fn pack(mut self) -> Result<PackedResult> {
        // Build a map of witness -> expression for packed predicates
        let mut substitutions: HashMap<WitnessVar, crate::expression::Expression> = HashMap::new();
        
        // Identify predicates to pack and mark their results as eliminated
        for predicate in &self.predicates {
            if let Some(decision) = self.decisions.get(&predicate.id()) {
                if decision.should_pack {
                    // This predicate's result will be eliminated
                    match predicate {
                        Predicate::Equals { result, expression, .. } => {
                            substitutions.insert(*result, expression.clone());
                            // Mark in graph as eliminated
                            self.graph.mark_eliminated(*result, expression.clone());
                        }
                        _ => {
                            // MUL predicates are never packed
                        }
                    }
                }
            }
        }
        
        // Apply substitutions to remaining predicates
        let mut packed_predicates = Vec::new();
        let predicates = std::mem::take(&mut self.predicates);
        for predicate in predicates {
            if let Some(decision) = self.decisions.get(&predicate.id()) {
                if decision.should_pack {
                    // Skip packed predicates - they're eliminated
                    continue;
                }
            }
            
            // Apply substitutions to this predicate's expressions
            let substituted = self.substitute_predicate(predicate, &substitutions)?;
            packed_predicates.push(substituted);
        }
        
        Ok(PackedResult {
            graph: self.graph,
            predicates: packed_predicates,
            decisions: self.decisions,
        })
    }
    
    /// Substitute expressions in a predicate
    fn substitute_predicate(
        &self,
        predicate: Predicate,
        substitutions: &HashMap<WitnessVar, crate::expression::Expression>,
    ) -> Result<Predicate> {
        match predicate {
            Predicate::Equals { id, result, expression } => {
                let substituted_expr = self.substitute_expression(expression, substitutions);
                Ok(Predicate::Equals {
                    id,
                    result,
                    expression: substituted_expr,
                })
            }
            Predicate::Multiply { id, hi, lo, a, b } => {
                let substituted_a = self.substitute_expression(a, substitutions);
                let substituted_b = self.substitute_expression(b, substitutions);
                Ok(Predicate::Multiply {
                    id,
                    hi,
                    lo,
                    a: substituted_a,
                    b: substituted_b,
                })
            }
        }
    }
    
    /// Substitute variables in an expression
    fn substitute_expression(
        &self,
        expr: crate::expression::Expression,
        substitutions: &HashMap<WitnessVar, crate::expression::Expression>,
    ) -> crate::expression::Expression {
        use crate::expression::Expression;
        
        match expr {
            Expression::Var(v) => {
                // Check if this variable should be substituted
                if let Some(substitution) = substitutions.get(&v) {
                    // Recursively substitute in the substitution
                    self.substitute_expression(substitution.clone(), substitutions)
                } else {
                    Expression::Var(v)
                }
            }
            Expression::Constant { value } => Expression::Constant { value },
            Expression::BinaryOp { op, left, right } => {
                // For recipe-based expressions, substitute individual witness variables
                let left_sub = if let Some(sub) = substitutions.get(&left) {
                    match sub {
                        Expression::Var(v) => *v,
                        _ => left, // Can't substitute non-variable expressions into witness positions
                    }
                } else {
                    left
                };
                let right_sub = if let Some(sub) = substitutions.get(&right) {
                    match sub {
                        Expression::Var(v) => *v,
                        _ => right,
                    }
                } else {
                    right
                };
                Expression::BinaryOp { op, left: left_sub, right: right_sub }
            }
            Expression::UnaryOp { op, input } => {
                let input_sub = if let Some(sub) = substitutions.get(&input) {
                    match sub {
                        Expression::Var(v) => *v,
                        _ => input,
                    }
                } else {
                    input
                };
                Expression::UnaryOp { op, input: input_sub }
            }
            Expression::Shift { input, variant, amount } => {
                let input_sub = if let Some(sub) = substitutions.get(&input) {
                    match sub {
                        Expression::Var(v) => *v,
                        _ => input,
                    }
                } else {
                    input
                };
                Expression::Shift { input: input_sub, variant, amount }
            }
            Expression::Multiply { left, right, is_high } => {
                let left_sub = if let Some(sub) = substitutions.get(&left) {
                    match sub {
                        Expression::Var(v) => *v,
                        _ => left,
                    }
                } else {
                    left
                };
                let right_sub = if let Some(sub) = substitutions.get(&right) {
                    match sub {
                        Expression::Var(v) => *v,
                        _ => right,
                    }
                } else {
                    right
                };
                Expression::Multiply { left: left_sub, right: right_sub, is_high }
            }
        }
    }
    
    /// Get the dependency graph
    pub fn graph(&self) -> &WitnessGraph {
        &self.graph
    }
}

/// Result of packing operation
pub struct PackedResult {
    pub graph: WitnessGraph,
    pub predicates: Vec<Predicate>,
    pub decisions: HashMap<PredicateId, PackingDecision>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{expression::Expression, witness::WitnessAllocator};
    
    #[test]
    fn test_packing_analysis() {
        let mut allocator = WitnessAllocator::new();
        let a = allocator.new_private();
        let b = allocator.new_private();
        let c = allocator.new_auxiliary();
        
        // Create packable predicate: c = a XOR b
        let predicate = Predicate::Equals {
            id: PredicateId(0),
            result: c,
            expression: Expression::xor(a, b),
        };
        
        let graph = WitnessGraph::from_predicates(&[predicate.clone()]).unwrap();
        let mut engine = PackingEngine::new(graph, vec![predicate], true); // Enable packing
        
        engine.analyze().unwrap();
        
        // Should decide to pack since c is not shared or output
        let decision = &engine.decisions[&PredicateId(0)];
        assert!(decision.should_pack);
        assert!(matches!(decision.reason, PackingReason::FreeOperation));
    }
}