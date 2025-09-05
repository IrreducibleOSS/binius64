//! Witness dependency graph for tracking computation flow

use std::collections::{HashMap, HashSet};

use crate::{
    error::{CompilerError, Result},
    expression::Expression,
    predicate::{Predicate, PredicateId},
    witness::WitnessVar,
};

/// Node in the witness dependency graph
#[derive(Debug, Clone)]
pub struct WitnessNode {
    pub var: WitnessVar,
    pub source: WitnessSource,
    pub consumed_by: HashSet<PredicateId>,
    pub is_output: bool,
}

/// How a witness value is produced
#[derive(Debug, Clone)]
pub enum WitnessSource {
    /// External input (public or private)
    External,
    
    /// Computed by a predicate
    Computed { predicate: PredicateId },
    
    /// Eliminated during packing but reconstructible
    Eliminated { expression: Box<Expression> },
    
    /// Constant value
    Constant { value: u64 },
}

/// Edge in the dependency graph
#[derive(Debug, Clone)]
pub struct DependencyEdge {
    pub from: WitnessVar,
    pub to: WitnessVar,
    pub via: PredicateId,
}

/// Dependency graph tracking witness relationships
#[derive(Debug)]
pub struct WitnessGraph {
    nodes: HashMap<WitnessVar, WitnessNode>,
    edges: Vec<DependencyEdge>,
    adjacency: HashMap<WitnessVar, Vec<WitnessVar>>,
}

impl WitnessGraph {
    /// Build dependency graph from predicates
    pub fn from_predicates(predicates: &[Predicate]) -> Result<Self> {
        let mut graph = Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
        };
        
        // First pass: identify all witness variables and their sources
        for predicate in predicates {
            // Register result variables as computed by this predicate
            for result_var in predicate.result_vars() {
                // Check for conflicting definitions
                if let Some(existing) = graph.nodes.get(&result_var) {
                    if !matches!(existing.source, WitnessSource::External) {
                        return Err(CompilerError::ConflictingDefinitions { var: result_var });
                    }
                }
                
                graph.nodes.insert(
                    result_var,
                    WitnessNode {
                        var: result_var,
                        source: WitnessSource::Computed {
                            predicate: predicate.id(),
                        },
                        consumed_by: HashSet::new(),
                        is_output: false, // Will be determined later
                    },
                );
            }
            
            // Register input variables
            for input_var in predicate.input_vars() {
                // Add edge from input to each result
                for result_var in predicate.result_vars() {
                    graph.edges.push(DependencyEdge {
                        from: input_var,
                        to: result_var,
                        via: predicate.id(),
                    });
                    
                    graph
                        .adjacency
                        .entry(input_var)
                        .or_default()
                        .push(result_var);
                }
                
                // Create node if it doesn't exist (external input)
                graph.nodes.entry(input_var).or_insert_with(|| {
                    WitnessNode {
                        var: input_var,
                        source: match input_var {
                            WitnessVar::Constant { value } => WitnessSource::Constant { value },
                            _ => WitnessSource::External,
                        },
                        consumed_by: HashSet::new(),
                        is_output: false,
                    }
                });
                
                // Mark this variable as consumed by the predicate
                graph
                    .nodes
                    .get_mut(&input_var)
                    .unwrap()
                    .consumed_by
                    .insert(predicate.id());
            }
        }
        
        // Check for cycles
        if graph.has_cycle()? {
            return Err(CompilerError::CyclicDependency);
        }
        
        Ok(graph)
    }
    
    /// Check if a witness is used by multiple predicates
    pub fn is_shared(&self, var: WitnessVar) -> bool {
        self.nodes
            .get(&var)
            .map(|node| node.consumed_by.len() > 1)
            .unwrap_or(false)
    }
    
    /// Check if a witness is marked as circuit output
    pub fn is_output(&self, var: WitnessVar) -> bool {
        self.nodes
            .get(&var)
            .map(|node| node.is_output)
            .unwrap_or(false)
    }
    
    /// Mark a witness as circuit output
    pub fn mark_output(&mut self, var: WitnessVar) {
        if let Some(node) = self.nodes.get_mut(&var) {
            node.is_output = true;
        }
    }
    
    /// Mark a witness as eliminated with its expansion
    pub fn mark_eliminated(&mut self, var: WitnessVar, expression: Expression) {
        if let Some(node) = self.nodes.get_mut(&var) {
            node.source = WitnessSource::Eliminated {
                expression: Box::new(expression),
            };
        }
    }
    
    /// Get topological ordering of witnesses for evaluation
    pub fn topological_order(&self) -> Result<Vec<WitnessVar>> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        let mut temp_visited = HashSet::new();
        
        for var in self.nodes.keys() {
            if !visited.contains(var) {
                self.dfs_topological(*var, &mut visited, &mut temp_visited, &mut order)?;
            }
        }
        
        order.reverse();
        Ok(order)
    }
    
    fn dfs_topological(
        &self,
        var: WitnessVar,
        visited: &mut HashSet<WitnessVar>,
        temp_visited: &mut HashSet<WitnessVar>,
        order: &mut Vec<WitnessVar>,
    ) -> Result<()> {
        if temp_visited.contains(&var) {
            return Err(CompilerError::CyclicDependency);
        }
        
        if visited.contains(&var) {
            return Ok(());
        }
        
        temp_visited.insert(var);
        
        // Visit dependencies first
        if let Some(deps) = self.adjacency.get(&var) {
            for dep in deps {
                self.dfs_topological(*dep, visited, temp_visited, order)?;
            }
        }
        
        temp_visited.remove(&var);
        visited.insert(var);
        order.push(var);
        
        Ok(())
    }
    
    /// Check if the graph has cycles
    fn has_cycle(&self) -> Result<bool> {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        
        for var in self.nodes.keys() {
            if !visited.contains(var) {
                if self.has_cycle_util(*var, &mut visited, &mut rec_stack)? {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }
    
    fn has_cycle_util(
        &self,
        var: WitnessVar,
        visited: &mut HashSet<WitnessVar>,
        rec_stack: &mut HashSet<WitnessVar>,
    ) -> Result<bool> {
        visited.insert(var);
        rec_stack.insert(var);
        
        if let Some(neighbors) = self.adjacency.get(&var) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    if self.has_cycle_util(*neighbor, visited, rec_stack)? {
                        return Ok(true);
                    }
                } else if rec_stack.contains(neighbor) {
                    return Ok(true);
                }
            }
        }
        
        rec_stack.remove(&var);
        Ok(false)
    }
    
    /// Get all nodes
    pub fn nodes(&self) -> &HashMap<WitnessVar, WitnessNode> {
        &self.nodes
    }
    
    /// Get a specific node
    pub fn get_node(&self, var: WitnessVar) -> Option<&WitnessNode> {
        self.nodes.get(&var)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{expression::Expression, witness::WitnessAllocator};
    
    #[test]
    fn test_dependency_graph_construction() {
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
        
        let graph = WitnessGraph::from_predicates(&[predicate]).unwrap();
        
        // Check nodes exist
        assert!(graph.nodes.contains_key(&a));
        assert!(graph.nodes.contains_key(&b));
        assert!(graph.nodes.contains_key(&c));
        
        // Check sources
        assert!(matches!(
            graph.nodes[&a].source,
            WitnessSource::External
        ));
        assert!(matches!(
            graph.nodes[&c].source,
            WitnessSource::Computed { .. }
        ));
    }
    
    #[test]
    fn test_cycle_detection() {
        let mut allocator = WitnessAllocator::new();
        let a = allocator.new_auxiliary();
        let b = allocator.new_auxiliary();
        
        // Create cyclic predicates: a = b, b = a
        let predicates = vec![
            Predicate::Equals {
                id: PredicateId(0),
                result: a,
                expression: Expression::var(b),
            },
            Predicate::Equals {
                id: PredicateId(1),
                result: b,
                expression: Expression::var(a),
            },
        ];
        
        let result = WitnessGraph::from_predicates(&predicates);
        assert!(matches!(result, Err(CompilerError::CyclicDependency)));
    }
}