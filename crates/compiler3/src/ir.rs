//! Intermediate representations for compilation phases

use crate::types::*;
use std::collections::{HashMap, HashSet};

/// Basic constraint before packing optimization
#[derive(Debug, Clone)]
pub enum BasicConstraint {
    /// Simple equality: result = expr
    Equals {
        result: WitnessId,
        expr: ConstraintExpr,
    },
    /// Multiplication with high/low outputs
    Multiply {
        left: WitnessId,
        right: WitnessId,
        hi: WitnessId,
        lo: WitnessId,
    },
}

/// Expression in constraint form (not semantic form)
#[derive(Debug, Clone)]
pub enum ConstraintExpr {
    Witness(WitnessId),
    Xor(Box<ConstraintExpr>, Box<ConstraintExpr>),
    And(Box<ConstraintExpr>, Box<ConstraintExpr>),
    Not(Box<ConstraintExpr>),
    Shift {
        input: Box<ConstraintExpr>,
        op: ShiftOp,
        amount: u8,
    },
}

/// Level 2 IR: Post-decomposition, pre-optimization
/// This is the CRITICAL stage where auxiliary computation is still explicit
#[derive(Debug, Clone)]
pub struct ConstraintIR {
    /// Basic constraints before packing
    pub constraints: Vec<BasicConstraint>,
    
    /// Dependency graph capturing ALL auxiliary computation
    /// This is preserved through packing!
    pub auxiliary_deps: AuxiliaryGraph,
    
    /// Map from auxiliary IDs to their computation recipes
    pub auxiliary_computation: HashMap<AuxiliaryId, AuxiliaryComputation>,
}

/// How to compute an auxiliary witness
#[derive(Debug, Clone)]
pub struct AuxiliaryComputation {
    pub id: AuxiliaryId,
    pub recipe: ComputationRecipe,
}

#[derive(Debug, Clone)]
pub enum ComputationRecipe {
    /// Direct computation from expression
    Direct(SemExpr),
    /// Existential (non-deterministic) computation
    Existential(ExistentialComputation),
    /// Computed but will be eliminated by packing
    Eliminable(SemExpr),
}

/// Level 3 IR: Post-optimization with preserved auxiliary computation
#[derive(Debug, Clone)]
pub struct PackedIR {
    /// Optimized constraints (auxiliaries eliminated)
    pub constraints: Vec<BiniusConstraint>,
    
    /// Which auxiliaries got packed away
    pub eliminated: HashSet<AuxiliaryId>,
    
    /// CRITICAL: Preserved from ConstraintIR
    /// This enables witness synthesis even for eliminated auxiliaries
    pub auxiliary_computer: AuxiliaryComputer,
}

/// Preserves auxiliary computation through packing
#[derive(Debug, Clone)]
pub struct AuxiliaryComputer {
    /// Original auxiliary dependency graph
    pub graph: AuxiliaryGraph,
    
    /// Computation recipes for ALL auxiliaries (including eliminated)
    pub recipes: HashMap<AuxiliaryId, AuxiliaryComputation>,
    
    /// Topological order for evaluation
    pub eval_order: Vec<AuxiliaryId>,
}

impl AuxiliaryComputer {
    /// Create from ConstraintIR, preserving all computation info
    pub fn from_constraint_ir(cir: &ConstraintIR) -> Self {
        let eval_order = Self::topological_sort(&cir.auxiliary_deps);
        
        Self {
            graph: cir.auxiliary_deps.clone(),
            recipes: cir.auxiliary_computation.clone(),
            eval_order,
        }
    }
    
    /// Topological sort for evaluation order
    fn topological_sort(graph: &AuxiliaryGraph) -> Vec<AuxiliaryId> {
        // Simple DFS-based topological sort
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        
        fn visit(
            id: AuxiliaryId,
            graph: &AuxiliaryGraph,
            visited: &mut HashSet<AuxiliaryId>,
            stack: &mut Vec<AuxiliaryId>,
        ) {
            if visited.contains(&id) {
                return;
            }
            visited.insert(id);
            
            // Visit dependencies first
            for (src, dst) in &graph.edges {
                if *dst == id {
                    visit(*src, graph, visited, stack);
                }
            }
            
            stack.push(id);
        }
        
        for node_id in graph.nodes.keys() {
            visit(*node_id, graph, &mut visited, &mut stack);
        }
        
        stack
    }
}