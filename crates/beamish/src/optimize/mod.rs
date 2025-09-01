//! Optimization framework for constraint generation

pub mod config;
pub mod rewrite;
pub mod templates;
pub mod cse;
pub mod canonicalize;

pub use config::OptConfig;
use crate::expr::ExprNode;
use crate::constraints::Constraint;
use crate::generate::delayed_binding::DelayedBindingBuilder;
use std::rc::Rc;

/// Main optimization pipeline
pub fn optimize_and_generate(expr: &ExprNode, config: &OptConfig) -> Vec<Constraint> {
    // Step 1: Expression rewriting (includes canonicalization)
    let rewritten = if config.has_any_rewriting() {
        rewrite::rewrite_expression(expr, config)
    } else if config.canonicalize_enabled {
        // Canonicalize for consistency
        canonicalize::canonicalize(expr)
    } else {
        // Skip canonicalization entirely
        expr.clone()
    };
    
    // Step 2: CSE detection
    let cse_marked = if config.cse_enabled {
        cse::detect_common_subexpressions(&rewritten)
    } else {
        rewritten
    };
    
    // Step 3: Constraint generation with templates
    let mut builder = DelayedBindingBuilder::new();
    
    // Add templates based on config
    if config.carry_chain_fusion {
        builder.add_template(Box::new(templates::CarryChainTemplate));
    }
    
    builder.build(&Rc::new(cse_marked))
}