//! Expression optimization and rewriting

use crate::expr::{Expr, ExprNode};
use std::rc::Rc;
use std::env;
use log::debug;

pub mod config;
pub mod rules;

pub use config::OptimizationConfig;

/// Check if verbose mode is enabled
fn is_verbose() -> bool {
    env::var("BEAMISH_VERBOSE").is_ok()
}

/// Stats tracking for optimization
pub struct OptimizationStats {
    pub xor_chains_merged: usize,
    pub double_nots_removed: usize,
    pub constants_folded: usize,
    pub identity_ops_removed: usize,
    pub total_nodes_before: usize,
    pub total_nodes_after: usize,
}

impl OptimizationStats {
    fn new() -> Self {
        OptimizationStats {
            xor_chains_merged: 0,
            double_nots_removed: 0,
            constants_folded: 0,
            identity_ops_removed: 0,
            total_nodes_before: 0,
            total_nodes_after: 0,
        }
    }
    
    fn total_optimizations(&self) -> usize {
        self.xor_chains_merged + self.double_nots_removed + 
        self.constants_folded + self.identity_ops_removed
    }
    
    fn report(&self) {
        if !is_verbose() {
            return;
        }
        
        eprintln!("[Optimizer] === Optimization Results ===");
        eprintln!("[Optimizer] Nodes: {} → {} (saved {})", 
            self.total_nodes_before, 
            self.total_nodes_after,
            self.total_nodes_before - self.total_nodes_after
        );
        
        if self.xor_chains_merged > 0 {
            eprintln!("[Optimizer]   XOR chains merged: {}", self.xor_chains_merged);
        }
        if self.double_nots_removed > 0 {
            eprintln!("[Optimizer]   Double NOTs removed: {}", self.double_nots_removed);
        }
        if self.constants_folded > 0 {
            eprintln!("[Optimizer]   Constants folded: {}", self.constants_folded);
        }
        if self.identity_ops_removed > 0 {
            eprintln!("[Optimizer]   Identity ops removed: {}", self.identity_ops_removed);
        }
        
        let total_optimizations = self.xor_chains_merged + self.double_nots_removed + 
                                  self.constants_folded + self.identity_ops_removed;
        
        if total_optimizations == 0 {
            eprintln!("[Optimizer]   (No optimizations applied - expression already optimal)");
        }
    }
}

/// Count nodes in an expression tree
fn count_nodes(node: &ExprNode) -> usize {
    use ExprNode::*;
    match node {
        Witness(_) | Constant(_) => 1,
        Not(a) | Shl(a, _) | Shr(a, _) | Sar(a, _) | Rol(a, _) | Ror(a, _) => {
            1 + count_nodes(a)
        }
        Xor(a, b) | And(a, b) | Or(a, b) | Add32(a, b) | Add64(a, b) | 
        Sub32(a, b) | Sub64(a, b) | Mul32(a, b) | Mul64(a, b) | Equal(a, b) => {
            1 + count_nodes(a) + count_nodes(b)
        }
        Mux(a, b, c) => {
            1 + count_nodes(a) + count_nodes(b) + count_nodes(c)
        }
    }
}

/// Optimize an expression by applying rewrite rules with custom configuration
pub fn optimize<T>(expr: &Expr<T>, config: &OptimizationConfig) -> Expr<T> {
    let mut stats = OptimizationStats::new();
    
    stats.total_nodes_before = count_nodes(&expr.inner);
    
    debug!(" OPTIMIZATION PHASE ");
    debug!("INPUT:  {} [{} nodes]", expr, stats.total_nodes_before);
    
    // Apply optimization passes with configuration
    let optimized = optimize_recursive(&expr.inner, config, &mut stats, 0, &mut 0);
    let result = Expr::wrap(optimized);
    
    stats.total_nodes_after = count_nodes(&result.inner);
    
    if stats.total_optimizations() > 0 {
        debug!("OUTPUT: {} [{} nodes]", result, stats.total_nodes_after);
        debug!("SAVED:  {} nodes", stats.total_nodes_before - stats.total_nodes_after);
    } else {
        debug!("OUTPUT: No changes needed (already optimal)");
    }
    
    // Also keep the old verbose mode for compatibility
    if is_verbose() {
        stats.report();
    }
    
    result
}

/// Optimize with default configuration (all optimizations enabled)
pub fn optimize_default<T>(expr: &Expr<T>) -> Expr<T> {
    optimize(expr, &OptimizationConfig::default())
}

/// Recursively optimize an expression node
fn optimize_recursive(
    node: &Rc<ExprNode>,
    config: &OptimizationConfig,
    stats: &mut OptimizationStats, 
    depth: usize,
    visit_count: &mut usize
) -> Rc<ExprNode> {
    use ExprNode::*;
    
    *visit_count += 1;
    
    // First, try to optimize this node directly
    if let Some((optimized, description)) = optimize_node(node, config) {
        // Track what kind of optimization we did
        if description.contains("→ 0") || description.contains("→ 1*") || description.contains("folded") {
            stats.constants_folded += 1;
        } else if description.contains("NOT(NOT") {
            stats.double_nots_removed += 1;
        } else if description.contains("XOR chain") {
            stats.xor_chains_merged += 1;
        } else {
            stats.identity_ops_removed += 1;
        }
        
        debug!("RULE:   {}", description);
        
        // Recursively optimize the result
        return optimize_recursive(&optimized, config, stats, depth, visit_count);
    }
    
    // Otherwise, recursively optimize children
    match &**node {
        Not(a) => {
            let opt_a = optimize_recursive(a, config, stats, depth + 1, visit_count);
            if opt_a != *a {
                Rc::new(Not(opt_a))
            } else {
                node.clone()
            }
        }
        Xor(a, b) => {
            let opt_a = optimize_recursive(a, config, stats, depth + 1, visit_count);
            let opt_b = optimize_recursive(b, config, stats, depth + 1, visit_count);
            if opt_a != *a || opt_b != *b {
                Rc::new(Xor(opt_a, opt_b))
            } else {
                node.clone()
            }
        }
        And(a, b) => {
            let opt_a = optimize_recursive(a, config, stats, depth + 1, visit_count);
            let opt_b = optimize_recursive(b, config, stats, depth + 1, visit_count);
            if opt_a != *a || opt_b != *b {
                Rc::new(And(opt_a, opt_b))
            } else {
                node.clone()
            }
        }
        Or(a, b) => {
            let opt_a = optimize_recursive(a, config, stats, depth + 1, visit_count);
            let opt_b = optimize_recursive(b, config, stats, depth + 1, visit_count);
            if opt_a != *a || opt_b != *b {
                Rc::new(Or(opt_a, opt_b))
            } else {
                node.clone()
            }
        }
        // Other binary ops
        Add32(a, b) | Add64(a, b) | Sub32(a, b) | Sub64(a, b) | 
        Mul32(a, b) | Mul64(a, b) | Equal(a, b) => {
            let opt_a = optimize_recursive(a, config, stats, depth + 1, visit_count);
            let opt_b = optimize_recursive(b, config, stats, depth + 1, visit_count);
            if opt_a != *a || opt_b != *b {
                match &**node {
                    Add32(_, _) => Rc::new(Add32(opt_a, opt_b)),
                    Add64(_, _) => Rc::new(Add64(opt_a, opt_b)),
                    Sub32(_, _) => Rc::new(Sub32(opt_a, opt_b)),
                    Sub64(_, _) => Rc::new(Sub64(opt_a, opt_b)),
                    Mul32(_, _) => Rc::new(Mul32(opt_a, opt_b)),
                    Mul64(_, _) => Rc::new(Mul64(opt_a, opt_b)),
                    Equal(_, _) => Rc::new(Equal(opt_a, opt_b)),
                    _ => unreachable!()
                }
            } else {
                node.clone()
            }
        }
        Mux(a, b, c) => {
            let opt_a = optimize_recursive(a, config, stats, depth + 1, visit_count);
            let opt_b = optimize_recursive(b, config, stats, depth + 1, visit_count);
            let opt_c = optimize_recursive(c, config, stats, depth + 1, visit_count);
            if opt_a != *a || opt_b != *b || opt_c != *c {
                Rc::new(Mux(opt_a, opt_b, opt_c))
            } else {
                node.clone()
            }
        }
        // Shift operations
        Shl(a, n) | Shr(a, n) | Sar(a, n) | Rol(a, n) | Ror(a, n) => {
            let opt_a = optimize_recursive(a, config, stats, depth + 1, visit_count);
            if opt_a != *a {
                match &**node {
                    Shl(_, n) => Rc::new(Shl(opt_a, *n)),
                    Shr(_, n) => Rc::new(Shr(opt_a, *n)),
                    Sar(_, n) => Rc::new(Sar(opt_a, *n)),
                    Rol(_, n) => Rc::new(Rol(opt_a, *n)),
                    Ror(_, n) => Rc::new(Ror(opt_a, *n)),
                    _ => unreachable!()
                }
            } else {
                node.clone()
            }
        }
        // Leaf nodes
        Witness(_) | Constant(_) => node.clone()
    }
}

/// Get a readable name for the node type
fn node_type_name(node: &ExprNode) -> &'static str {
    use ExprNode::*;
    match node {
        Witness(_) => "Witness",
        Constant(_) => "Constant",
        Xor(_, _) => "Xor",
        And(_, _) => "And",
        Or(_, _) => "Or",
        Not(_) => "Not",
        Shl(_, _) => "Shl",
        Shr(_, _) => "Shr",
        Sar(_, _) => "Sar",
        Rol(_, _) => "Rol",
        Ror(_, _) => "Ror",
        Add32(_, _) => "Add32",
        Add64(_, _) => "Add64",
        Sub32(_, _) => "Sub32",
        Sub64(_, _) => "Sub64",
        Mul32(_, _) => "Mul32",
        Mul64(_, _) => "Mul64",
        Mux(_, _, _) => "Mux",
        Equal(_, _) => "Equal",
    }
}

/// Apply optimization rules to a node based on configuration
pub fn optimize_node(node: &ExprNode, config: &OptimizationConfig) -> Option<(Rc<ExprNode>, &'static str)> {
    // Get enabled rules based on config and try each one
    for (description, rule) in rules::get_enabled_rules(config) {
        if let Some(optimized) = rule(node) {
            return Some((optimized, description));
        }
    }
    None
}