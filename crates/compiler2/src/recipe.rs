//! Witness recipe compilation - generates computation instructions

use std::collections::HashMap;

use crate::{
    error::Result,
    expression::Expression,
    predicate::PredicateId,
    witness::WitnessVar,
};

/// A node in the witness dependency graph
#[derive(Debug, Clone)]
pub struct WitnessNode {
    pub var: WitnessVar,
    pub recipe: WitnessRecipe,
    pub consumed_by: Vec<PredicateId>,
    pub required_for_output: bool,
}

/// How to compute a witness value
#[derive(Debug, Clone)]
pub enum WitnessRecipe {
    /// Value provided as input (external)
    Input,
    
    /// Value computed from other witnesses
    Compute {
        op: Operation,
        inputs: Vec<WitnessVar>,
    },
    
    /// Value eliminated by packing but still computable
    Eliminated {
        expanded: Box<Expression>,
    },
}

/// Computational operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Xor,
    And,
    Not,
    Shift {
        variant: crate::expression::ShiftVariant,
        amount: u8,
    },
    Multiply {
        is_high: bool,
    },
}

/// The witness dependency graph with recipes
#[derive(Debug, Clone)]
pub struct WitnessGraph {
    pub nodes: HashMap<WitnessVar, WitnessNode>,
    pub edges: Vec<(WitnessVar, WitnessVar)>, // source → target dependencies
}

impl WitnessGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }
    
    /// Add a node to the graph
    pub fn add_node(&mut self, node: WitnessNode) {
        self.nodes.insert(node.var, node);
    }
    
    /// Add a dependency edge
    pub fn add_edge(&mut self, from: WitnessVar, to: WitnessVar) {
        self.edges.push((from, to));
    }
    
    /// Mark a witness as eliminated but keep its recipe
    pub fn mark_eliminated(&mut self, var: WitnessVar, expanded: Expression) {
        if let Some(node) = self.nodes.get_mut(&var) {
            node.recipe = WitnessRecipe::Eliminated {
                expanded: Box::new(expanded),
            };
        }
    }
    
    /// Get topological order for evaluation
    pub fn topological_order(&self) -> Result<Vec<WitnessVar>> {
        // Simple topological sort (TODO: detect cycles)
        let mut visited = HashMap::new();
        let mut order = Vec::new();
        
        for node in self.nodes.keys() {
            self.visit_node(*node, &mut visited, &mut order)?;
        }
        
        Ok(order)
    }
    
    fn visit_node(
        &self,
        var: WitnessVar,
        visited: &mut HashMap<WitnessVar, bool>,
        order: &mut Vec<WitnessVar>,
    ) -> Result<()> {
        if let Some(&in_progress) = visited.get(&var) {
            if in_progress {
                return Err(crate::error::CompilerError::RecipeCompilation {
                    reason: "Cyclic dependency detected".to_string(),
                });
            }
            return Ok(());
        }
        
        visited.insert(var, true);
        
        // Visit dependencies first
        for (from, to) in &self.edges {
            if *to == var {
                self.visit_node(*from, visited, order)?;
            }
        }
        
        visited.insert(var, false);
        order.push(var);
        Ok(())
    }
}

/// Compiles witness recipes from predicates
pub struct RecipeCompiler {
    graph: WitnessGraph,
    predicates: Vec<crate::predicate::Predicate>,
}

impl RecipeCompiler {
    /// Create compiler from predicates
    pub fn from_predicates(predicates: Vec<crate::predicate::Predicate>) -> Self {
        Self {
            graph: WitnessGraph::new(),
            predicates,
        }
    }
    
    /// Build the witness dependency graph from predicates
    pub fn build_graph(mut self) -> Result<WitnessGraph> {
        // First pass: create nodes for all witnesses
        for predicate in &self.predicates {
            match predicate {
                crate::predicate::Predicate::Equals { result, expression, id } => {
                    // Create node for result witness
                    let recipe = self.expression_to_recipe(expression)?;
                    let node = WitnessNode {
                        var: *result,
                        recipe,
                        consumed_by: vec![*id],
                        required_for_output: false, // TODO: determine from context
                    };
                    self.graph.add_node(node);
                    
                    // Add edges for dependencies
                    for dep in expression.collect_vars() {
                        self.graph.add_edge(dep, *result);
                    }
                }
                crate::predicate::Predicate::Multiply { a, b, hi, lo, id } => {
                    // Extract input witnesses
                    let a_var = match a {
                        Expression::Var(v) => *v,
                        _ => continue, // Skip complex expressions for now
                    };
                    let b_var = match b {
                        Expression::Var(v) => *v,
                        _ => continue,
                    };
                    
                    // Create nodes for hi and lo outputs
                    let hi_node = WitnessNode {
                        var: *hi,
                        recipe: WitnessRecipe::Compute {
                            op: Operation::Multiply { is_high: true },
                            inputs: vec![a_var, b_var],
                        },
                        consumed_by: vec![*id],
                        required_for_output: false,
                    };
                    
                    let lo_node = WitnessNode {
                        var: *lo,
                        recipe: WitnessRecipe::Compute {
                            op: Operation::Multiply { is_high: false },
                            inputs: vec![a_var, b_var],
                        },
                        consumed_by: vec![*id],
                        required_for_output: false,
                    };
                    
                    self.graph.add_node(hi_node);
                    self.graph.add_node(lo_node);
                    self.graph.add_edge(a_var, *hi);
                    self.graph.add_edge(b_var, *hi);
                    self.graph.add_edge(a_var, *lo);
                    self.graph.add_edge(b_var, *lo);
                }
            }
        }
        
        // Add input nodes for witnesses that aren't computed
        let computed_vars: Vec<_> = self.graph.nodes.keys().copied().collect();
        for predicate in &self.predicates {
            for var in predicate.collect_witnesses() {
                if !computed_vars.contains(&var) {
                    let node = WitnessNode {
                        var,
                        recipe: WitnessRecipe::Input,
                        consumed_by: vec![],
                        required_for_output: false,
                    };
                    self.graph.add_node(node);
                }
            }
        }
        
        Ok(self.graph)
    }
    
    /// Convert expression to recipe (for simple cases)
    fn expression_to_recipe(&self, expr: &Expression) -> Result<WitnessRecipe> {
        match expr {
            Expression::Var(_) => Ok(WitnessRecipe::Input),
            Expression::Xor(a, b) => {
                let inputs = self.extract_inputs(vec![a, b])?;
                Ok(WitnessRecipe::Compute {
                    op: Operation::Xor,
                    inputs,
                })
            }
            Expression::And(a, b) => {
                let inputs = self.extract_inputs(vec![a, b])?;
                Ok(WitnessRecipe::Compute {
                    op: Operation::And,
                    inputs,
                })
            }
            Expression::Not(a) => {
                let inputs = self.extract_inputs(vec![a])?;
                Ok(WitnessRecipe::Compute {
                    op: Operation::Not,
                    inputs,
                })
            }
            _ => {
                // Complex expressions become eliminated recipes
                Ok(WitnessRecipe::Eliminated {
                    expanded: Box::new(expr.clone()),
                })
            }
        }
    }
    
    fn extract_inputs(&self, exprs: Vec<&Box<Expression>>) -> Result<Vec<WitnessVar>> {
        let mut inputs = Vec::new();
        for expr in exprs {
            match &**expr {
                Expression::Var(v) => inputs.push(*v),
                _ => {
                    // Complex sub-expression - can't extract simple inputs
                    return Err(crate::error::CompilerError::RecipeCompilation {
                        reason: "Complex nested expression in recipe".to_string(),
                    });
                }
            }
        }
        Ok(inputs)
    }
}

/// Compiled witness recipes ready for execution
#[derive(Debug)]
pub struct CompiledRecipes {
    pub graph: WitnessGraph,
    pub eval_order: Vec<WitnessVar>,
}

impl CompiledRecipes {
    /// Create from witness graph
    pub fn from_graph(graph: WitnessGraph) -> Result<Self> {
        let eval_order = graph.topological_order()?;
        Ok(Self {
            graph,
            eval_order,
        })
    }
    
    /// Get node for a specific witness
    pub fn get_node(&self, var: WitnessVar) -> Option<&WitnessNode> {
        self.graph.nodes.get(&var)
    }
    
    /// Get recipe for a specific witness
    pub fn get_recipe(&self, var: WitnessVar) -> Option<&WitnessRecipe> {
        self.graph.nodes.get(&var).map(|node| &node.recipe)
    }
    
    /// Get evaluation order
    pub fn eval_order(&self) -> &[WitnessVar] {
        &self.eval_order
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expression::Expression,
        predicate::{Predicate, PredicateId},
        witness::WitnessAllocator,
    };
    
    #[test]
    fn test_recipe_compilation() {
        let mut allocator = WitnessAllocator::new();
        let a = allocator.new_private();
        let b = allocator.new_private();
        let c = allocator.new_auxiliary();
        
        let predicate = Predicate::Equals {
            id: PredicateId(0),
            result: c,
            expression: Expression::xor(Expression::var(a), Expression::var(b)),
        };
        
        let compiler = RecipeCompiler::from_predicates(vec![predicate]);
        let graph = compiler.build_graph().unwrap();
        let recipes = CompiledRecipes::from_graph(graph).unwrap();
        
        // Should have recipes for all three witnesses
        assert_eq!(recipes.graph.nodes.len(), 3);
        assert!(recipes.get_recipe(a).is_some());
        assert!(recipes.get_recipe(b).is_some());
        assert!(recipes.get_recipe(c).is_some());
    }
}