//! Decomposition: Transform semantic expressions into constraints
//! 
//! This is where we capture auxiliary computation BEFORE packing destroys it!

use crate::types::*;
use crate::ir::*;
use std::collections::HashMap;

/// Decomposes semantic expressions into basic constraints
pub struct Decomposer {
    /// Counter for generating fresh auxiliary IDs
    next_auxiliary_id: u32,
    
    /// Accumulated constraints
    constraints: Vec<BasicConstraint>,
    
    /// Auxiliary dependency graph being built
    auxiliary_graph: AuxiliaryGraph,
    
    /// Auxiliary computation recipes
    auxiliary_computation: HashMap<AuxiliaryId, AuxiliaryComputation>,
}

impl Decomposer {
    pub fn new() -> Self {
        Self {
            next_auxiliary_id: 0,
            constraints: Vec::new(),
            auxiliary_graph: AuxiliaryGraph {
                nodes: HashMap::new(),
                edges: Vec::new(),
            },
            auxiliary_computation: HashMap::new(),
        }
    }
    
    /// Main decomposition entry point
    pub fn decompose(mut self, expr: SemExpr) -> Result<ConstraintIR, String> {
        let _result = self.decompose_expr(expr)?;
        
        Ok(ConstraintIR {
            constraints: self.constraints,
            auxiliary_deps: self.auxiliary_graph,
            auxiliary_computation: self.auxiliary_computation,
        })
    }
    
    /// Decompose a semantic expression, returning the witness that holds the result
    fn decompose_expr(&mut self, expr: SemExpr) -> Result<WitnessId, String> {
        match expr {
            SemExpr::Var(var_id) => {
                // Variables map to witnesses (public or auxiliary)
                // For now, treat as public
                Ok(WitnessId::Public(PublicId(var_id.0)))
            }
            
            SemExpr::Const(value) => {
                // Constants become auxiliary witnesses with fixed values
                let aux_id = self.fresh_auxiliary();
                self.add_auxiliary_computation(
                    aux_id,
                    ComputationRecipe::Direct(SemExpr::Const(value)),
                );
                Ok(WitnessId::Auxiliary(aux_id))
            }
            
            // Bitwise operations map directly to constraints
            SemExpr::Xor(a, b) => {
                let a_witness = self.decompose_expr(*a)?;
                let b_witness = self.decompose_expr(*b)?;
                let result = self.fresh_auxiliary();
                
                // CRITICAL: Capture computation recipe BEFORE it becomes a constraint
                self.add_auxiliary_computation(
                    result,
                    ComputationRecipe::Direct(SemExpr::Xor(
                        Box::new(Self::witness_to_sem_expr(a_witness)),
                        Box::new(Self::witness_to_sem_expr(b_witness)),
                    )),
                );
                
                // Generate constraint: result = a ⊕ b
                self.constraints.push(BasicConstraint::Equals {
                    result: WitnessId::Auxiliary(result),
                    expr: ConstraintExpr::Xor(
                        Box::new(ConstraintExpr::Witness(a_witness)),
                        Box::new(ConstraintExpr::Witness(b_witness)),
                    ),
                });
                
                // Add edges to dependency graph
                self.add_dependency(a_witness, result);
                self.add_dependency(b_witness, result);
                
                Ok(WitnessId::Auxiliary(result))
            }
            
            SemExpr::And(a, b) => {
                let a_witness = self.decompose_expr(*a)?;
                let b_witness = self.decompose_expr(*b)?;
                let result = self.fresh_auxiliary();
                
                self.add_auxiliary_computation(
                    result,
                    ComputationRecipe::Direct(SemExpr::And(
                        Box::new(Self::witness_to_sem_expr(a_witness)),
                        Box::new(Self::witness_to_sem_expr(b_witness)),
                    )),
                );
                
                self.constraints.push(BasicConstraint::Equals {
                    result: WitnessId::Auxiliary(result),
                    expr: ConstraintExpr::And(
                        Box::new(ConstraintExpr::Witness(a_witness)),
                        Box::new(ConstraintExpr::Witness(b_witness)),
                    ),
                });
                
                self.add_dependency(a_witness, result);
                self.add_dependency(b_witness, result);
                
                Ok(WitnessId::Auxiliary(result))
            }
            
            // Division creates existential auxiliary for quotient
            SemExpr::Div(dividend_expr, divisor_expr) => {
                let dividend = self.decompose_expr(*dividend_expr)?;
                let divisor = self.decompose_expr(*divisor_expr)?;
                
                // Create existential auxiliary for quotient
                let quotient = self.fresh_auxiliary();
                let remainder = self.fresh_auxiliary();
                
                // CRITICAL: Capture existential computation
                self.add_auxiliary_computation(
                    quotient,
                    ComputationRecipe::Existential(ExistentialComputation::DivQuotient {
                        dividend,
                        divisor,
                    }),
                );
                
                // Result is the quotient
                // Constraint: dividend = divisor × quotient + remainder
                // This needs to be further decomposed into MUL constraint
                self.constraints.push(BasicConstraint::Multiply {
                    left: divisor,
                    right: WitnessId::Auxiliary(quotient),
                    hi: WitnessId::Auxiliary(self.fresh_auxiliary()),
                    lo: WitnessId::Auxiliary(self.fresh_auxiliary()),
                });
                
                // TODO: Add constraint for remainder < divisor
                
                self.add_dependency(dividend, quotient);
                self.add_dependency(divisor, quotient);
                
                Ok(WitnessId::Auxiliary(quotient))
            }
            
            SemExpr::Mod(dividend_expr, divisor_expr) => {
                let dividend = self.decompose_expr(*dividend_expr)?;
                let divisor = self.decompose_expr(*divisor_expr)?;
                
                // Create existential auxiliary for quotient
                let quotient = self.fresh_auxiliary();
                let remainder = self.fresh_auxiliary();
                
                self.add_auxiliary_computation(
                    quotient,
                    ComputationRecipe::Existential(ExistentialComputation::DivQuotient {
                        dividend,
                        divisor,
                    }),
                );
                
                self.add_auxiliary_computation(
                    remainder,
                    ComputationRecipe::Direct(SemExpr::Mod(
                        Box::new(Self::witness_to_sem_expr(dividend)),
                        Box::new(Self::witness_to_sem_expr(divisor)),
                    )),
                );
                
                // Constraint: dividend = divisor × quotient + remainder
                self.constraints.push(BasicConstraint::Multiply {
                    left: divisor,
                    right: WitnessId::Auxiliary(quotient),
                    hi: WitnessId::Auxiliary(self.fresh_auxiliary()),
                    lo: WitnessId::Auxiliary(self.fresh_auxiliary()),
                });
                
                self.add_dependency(dividend, remainder);
                self.add_dependency(divisor, remainder);
                
                Ok(WitnessId::Auxiliary(remainder))
            }
            
            _ => Err("Unsupported semantic expression".to_string()),
        }
    }
    
    /// Generate a fresh auxiliary ID
    fn fresh_auxiliary(&mut self) -> AuxiliaryId {
        let id = AuxiliaryId(self.next_auxiliary_id);
        self.next_auxiliary_id += 1;
        id
    }
    
    /// Add auxiliary computation recipe
    fn add_auxiliary_computation(&mut self, id: AuxiliaryId, recipe: ComputationRecipe) {
        let node = AuxiliaryNode {
            id,
            source: match &recipe {
                ComputationRecipe::Direct(expr) => AuxiliarySource::Computed(Box::new(expr.clone())),
                ComputationRecipe::Existential(comp) => AuxiliarySource::Existential(comp.clone()),
                ComputationRecipe::Eliminable(expr) => AuxiliarySource::Computed(Box::new(expr.clone())),
            },
            dependents: Vec::new(),
            elimination_status: EliminationStatus::Required, // Will be updated by packing
        };
        
        self.auxiliary_graph.nodes.insert(id, node);
        self.auxiliary_computation.insert(id, AuxiliaryComputation {
            id,
            recipe,
        });
    }
    
    /// Add dependency edge to graph
    fn add_dependency(&mut self, from: WitnessId, to: AuxiliaryId) {
        if let WitnessId::Auxiliary(from_aux) = from {
            self.auxiliary_graph.edges.push((from_aux, to));
            
            if let Some(node) = self.auxiliary_graph.nodes.get_mut(&from_aux) {
                node.dependents.push(to);
            }
        }
    }
    
    /// Convert witness ID to semantic expression for recipe preservation
    fn witness_to_sem_expr(witness: WitnessId) -> SemExpr {
        match witness {
            WitnessId::Public(id) => SemExpr::Var(VarId(id.0)),
            WitnessId::Auxiliary(id) => SemExpr::Auxiliary {
                id,
                verifier: Box::new(SemExpr::Var(VarId(id.0))),
            },
        }
    }
}