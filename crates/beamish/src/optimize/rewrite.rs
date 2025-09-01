//! Expression rewriting optimizations

use crate::expr::ExprNode;
use crate::optimize::{OptConfig, canonicalize::canonicalize};
use std::rc::Rc;

/// Rewrite expressions to optimal forms
/// This includes canonicalization as a preprocessing step to ensure robust pattern matching
pub fn rewrite_expression(expr: &ExprNode, config: &OptConfig) -> ExprNode {
    // Step 1: Canonicalize for robust pattern matching
    // This is a form of rewriting that normalizes expressions to a standard form
    let canonical = canonicalize(expr);
    
    // Step 2: Apply optimization rewrites
    rewrite_expression_impl(&canonical, config)
}

/// Internal implementation of expression rewriting after canonicalization
fn rewrite_expression_impl(expr: &ExprNode, config: &OptConfig) -> ExprNode {
    match expr {
        // XOR optimizations - check patterns first, then simpler optimizations
        ExprNode::Xor(a, b) => {
            // First check for conditional select pattern (highest priority)
            if config.conditional_select_rewrite {
                if let Some((sel_a, sel_b, sel_c)) = detect_conditional_select_pattern(expr) {
                    // Rewrite to: a & (b⊕c) ⊕ c
                    let b_xor_c = ExprNode::Xor(Rc::clone(&sel_b), Rc::clone(&sel_c));
                    let and_part = ExprNode::And(Rc::clone(&sel_a), Rc::new(b_xor_c));
                    return ExprNode::Xor(Rc::new(and_part), sel_c);
                }
            }
            
            // Check for XOR of ANDs pattern: (a&b)⊕(a&c)⊕(b&c)
            if config.xor_of_ands_rewrite {
                if let Some((a, b, c)) = detect_xor_of_ands_pattern(expr) {
                    // Rewrite to: (a⊕c) & (b⊕c) ⊕ c
                    let a_xor_c = ExprNode::Xor(Rc::clone(&a), Rc::clone(&c));
                    let b_xor_c = ExprNode::Xor(Rc::clone(&b), Rc::clone(&c));
                    let and_part = ExprNode::And(Rc::new(a_xor_c), Rc::new(b_xor_c));
                    return ExprNode::Xor(Rc::new(and_part), c);
                }
            }
            
            // Then check XOR term cancellation and simpler optimizations
            if config.xor_term_cancellation {
            // First check simpler optimizations
            // XOR self-elimination: x ⊕ x → 0
            if config.xor_self_elimination && a == b {
                return ExprNode::Constant(0);
            }
            
            // XOR with zero elimination: x ⊕ 0 → x
            if config.xor_zero_elimination {
                match (a.as_ref(), b.as_ref()) {
                    (ExprNode::Constant(0), _) => return (**b).clone(),
                    (_, ExprNode::Constant(0)) => return (**a).clone(),
                    _ => {}
                }
            }
            
            // XOR with ones elimination: x ⊕ 1* → ~x
            if config.xor_ones_elimination {
                match (a.as_ref(), b.as_ref()) {
                    (ExprNode::Constant(0xFFFFFFFFFFFFFFFF), _) => {
                        return ExprNode::Not(Rc::new(rewrite_expression_impl(b, config)));
                    }
                    (_, ExprNode::Constant(0xFFFFFFFFFFFFFFFF)) => {
                        return ExprNode::Not(Rc::new(rewrite_expression_impl(a, config)));
                    }
                    _ => {}
                }
            }
            
            // Try XOR term cancellation
            if let Some(simplified) = try_cancel_xor_terms(a, b) {
                return rewrite_expression_impl(&simplified, config);
            }
            
            }
            
            // Default: recurse on children
            ExprNode::Xor(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        
        
        // AND with zero or ones
        ExprNode::And(a, b) => {
            // Check for self elimination: x & x → x
            if config.and_self_elimination && a == b {
                return rewrite_expression_impl(a, config);
            }
            
            // Check for zero elimination: x & 0 → 0
            if config.and_zero_elimination {
                match (a.as_ref(), b.as_ref()) {
                    (ExprNode::Constant(0), _) | (_, ExprNode::Constant(0)) => {
                        return ExprNode::Constant(0);
                    }
                    _ => {}
                }
            }
            
            // Check for ones elimination: x & 0xFFFF... → x
            if config.and_ones_elimination {
                match (a.as_ref(), b.as_ref()) {
                    (ExprNode::Constant(0xFFFFFFFFFFFFFFFF), _) => {
                        return rewrite_expression_impl(b, config);
                    }
                    (_, ExprNode::Constant(0xFFFFFFFFFFFFFFFF)) => {
                        return rewrite_expression_impl(a, config);
                    }
                    _ => {}
                }
            }
            
            // Default: recurse on children
            ExprNode::And(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        
        // OR simplifications
        ExprNode::Or(a, b) => {
            // Check for self elimination: x | x → x
            if config.or_self_elimination && a == b {
                return rewrite_expression_impl(a, config);
            }
            
            // Check for zero elimination: x | 0 → x
            if config.or_zero_elimination {
                match (a.as_ref(), b.as_ref()) {
                    (ExprNode::Constant(0), _) => return rewrite_expression_impl(b, config),
                    (_, ExprNode::Constant(0)) => return rewrite_expression_impl(a, config),
                    _ => {}
                }
            }
            
            // Check for ones elimination: x | 1* → 1*
            if config.or_ones_elimination {
                match (a.as_ref(), b.as_ref()) {
                    (ExprNode::Constant(0xFFFFFFFFFFFFFFFF), _) | 
                    (_, ExprNode::Constant(0xFFFFFFFFFFFFFFFF)) => {
                        return ExprNode::Constant(0xFFFFFFFFFFFFFFFF);
                    }
                    _ => {}
                }
            }
            
            // Default: recurse on children
            ExprNode::Or(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        
        // NOT simplifications
        ExprNode::Not(inner) => {
            // Double NOT elimination: ~~x → x
            if config.double_not_elimination {
                if let ExprNode::Not(double_inner) = inner.as_ref() {
                    return rewrite_expression_impl(double_inner, config);
                }
            }
            
            // NOT constant elimination: ~0 → 1*, ~1* → 0
            if config.not_const_elimination {
                match inner.as_ref() {
                    ExprNode::Constant(0) => return ExprNode::Constant(0xFFFFFFFFFFFFFFFF),
                    ExprNode::Constant(0xFFFFFFFFFFFFFFFF) => return ExprNode::Constant(0),
                    _ => {}
                }
            }
            
            // Default: recurse on child
            ExprNode::Not(Rc::new(rewrite_expression_impl(inner, config)))
        }
        
        
        // Default: recurse on children
        ExprNode::Witness(v) => ExprNode::Witness(*v),
        ExprNode::Constant(c) => ExprNode::Constant(*c),
        ExprNode::Shl(a, amt) => {
            ExprNode::Shl(Rc::new(rewrite_expression_impl(a, config)), *amt)
        }
        ExprNode::Shr(a, amt) => {
            ExprNode::Shr(Rc::new(rewrite_expression_impl(a, config)), *amt)
        }
        ExprNode::Sar(a, amt) => {
            ExprNode::Sar(Rc::new(rewrite_expression_impl(a, config)), *amt)
        }
        ExprNode::Rol(a, amt) => {
            ExprNode::Rol(Rc::new(rewrite_expression_impl(a, config)), *amt)
        }
        ExprNode::Ror(a, amt) => {
            ExprNode::Ror(Rc::new(rewrite_expression_impl(a, config)), *amt)
        }
        ExprNode::Add32(a, b) => {
            ExprNode::Add32(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        ExprNode::Add64(a, b) => {
            ExprNode::Add64(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        ExprNode::Sub32(a, b) => {
            ExprNode::Sub32(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        ExprNode::Sub64(a, b) => {
            ExprNode::Sub64(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        ExprNode::Mul32(a, b) => {
            ExprNode::Mul32(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        ExprNode::Mul64(a, b) => {
            ExprNode::Mul64(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        ExprNode::Mux(cond, t, f) => {
            ExprNode::Mux(
                Rc::new(rewrite_expression_impl(cond, config)),
                Rc::new(rewrite_expression_impl(t, config)),
                Rc::new(rewrite_expression_impl(f, config))
            )
        }
        ExprNode::Equal(a, b) => {
            ExprNode::Equal(
                Rc::new(rewrite_expression_impl(a, config)),
                Rc::new(rewrite_expression_impl(b, config))
            )
        }
        
        ExprNode::BlackBox { compute, inputs } => {
            // Process inputs recursively, but keep compute function unchanged
            let rewritten_inputs: Vec<Rc<ExprNode>> = inputs.iter()
                .map(|input| Rc::new(rewrite_expression_impl(input, config)))
                .collect();
            ExprNode::BlackBox {
                compute: *compute,
                inputs: rewritten_inputs,
            }
        }
    }
}

/// Detect XOR of AND terms pattern: combinations like (a&b) ⊕ (a&c) ⊕ (b&c)
fn detect_xor_of_ands_pattern(expr: &ExprNode) -> Option<(Rc<ExprNode>, Rc<ExprNode>, Rc<ExprNode>)> {
    // Flatten XOR chain to get all terms
    let terms = collect_xor_terms(expr);
    
    // We need exactly 3 AND terms for majority pattern
    if terms.len() != 3 {
        return None;
    }
    
    // Extract AND operands from each term
    let mut and_pairs = Vec::new();
    for term in &terms {
        if let ExprNode::And(left, right) = term.as_ref() {
            and_pairs.push((left.clone(), right.clone()));
        } else {
            return None; // All terms must be AND operations
        }
    }
    
    // We have 3 AND pairs, check if they form majority pattern
    // The pattern is: (a&b), (a&c), (b&c) in any order
    // Each variable should appear exactly twice
    
    // Count occurrences of each unique operand
    let mut operand_counts = std::collections::HashMap::new();
    for (left, right) in &and_pairs {
        *operand_counts.entry(format!("{:?}", left)).or_insert(0) += 1;
        *operand_counts.entry(format!("{:?}", right)).or_insert(0) += 1;
    }
    
    // Each of the 3 variables should appear exactly twice
    if operand_counts.len() != 3 {
        return None;
    }
    for count in operand_counts.values() {
        if *count != 2 {
            return None;
        }
    }
    
    // Find the three unique variables
    let mut vars = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (left, right) in &and_pairs {
        let left_key = format!("{:?}", left);
        let right_key = format!("{:?}", right);
        if !seen.contains(&left_key) {
            vars.push(left.clone());
            seen.insert(left_key);
        }
        if !seen.contains(&right_key) {
            vars.push(right.clone());
            seen.insert(right_key);
        }
    }
    
    if vars.len() == 3 {
        Some((vars[0].clone(), vars[1].clone(), vars[2].clone()))
    } else {
        None
    }
}

/// Detect conditional select pattern: (a&b) ⊕ ((~a)&c) 
fn detect_conditional_select_pattern(expr: &ExprNode) -> Option<(Rc<ExprNode>, Rc<ExprNode>, Rc<ExprNode>)> {
    if let ExprNode::Xor(left, right) = expr {
        // Check for (a&b) on left
        if let ExprNode::And(a, b) = left.as_ref() {
            // Check for ((~a2)&c) or (c&(~a2)) on right (canonicalization may reorder)
            if let ExprNode::And(term1, term2) = right.as_ref() {
                // Try both orders
                if let ExprNode::Not(a2) = term1.as_ref() {
                    if a == a2 {
                        return Some((Rc::clone(a), Rc::clone(b), Rc::clone(term2)));
                    }
                }
                if let ExprNode::Not(a2) = term2.as_ref() {
                    if a == a2 {
                        return Some((Rc::clone(a), Rc::clone(b), Rc::clone(term1)));
                    }
                }
            }
        }
        // Also check reversed order
        if let ExprNode::And(term1, term2) = left.as_ref() {
            // Check if one term is NOT
            let (not_a_opt, c_opt) = if let ExprNode::Not(a) = term1.as_ref() {
                (Some(a), Some(term2))
            } else if let ExprNode::Not(a) = term2.as_ref() {
                (Some(a), Some(term1))
            } else {
                (None, None)
            };
            
            if let (Some(a), Some(c)) = (not_a_opt, c_opt) {
                if let ExprNode::And(a2, b) = right.as_ref() {
                    if a == a2 {
                        return Some((Rc::clone(a), Rc::clone(b), Rc::clone(c)));
                    }
                }
            }
        }
    }
    None
}

/// Try to cancel common XOR terms
fn try_cancel_xor_terms(left: &Rc<ExprNode>, right: &Rc<ExprNode>) -> Option<ExprNode> {
    // Collect all XOR terms from both sides
    let left_terms = collect_xor_terms(left);
    let right_terms = collect_xor_terms(right);
    
    // Find common terms
    let mut cancelled_left = left_terms.clone();
    let mut cancelled_right = right_terms.clone();
    
    for left_term in &left_terms {
        if let Some(pos) = cancelled_right.iter().position(|r| r == left_term) {
            // Found matching term - remove from both sides (cancellation)
            if let Some(left_pos) = cancelled_left.iter().position(|l| l == left_term) {
                cancelled_left.remove(left_pos);
                cancelled_right.remove(pos);
            }
        }
    }
    
    // If we cancelled anything, rebuild the expression
    if cancelled_left.len() != left_terms.len() || cancelled_right.len() != right_terms.len() {
        // Rebuild from remaining terms
        let new_expr = rebuild_xor_from_terms(&cancelled_left, &cancelled_right);
        return Some(new_expr);
    }
    
    None
}

/// Collect all terms in a XOR chain
fn collect_xor_terms(expr: &ExprNode) -> Vec<Rc<ExprNode>> {
    match expr {
        ExprNode::Xor(a, b) => {
            let mut terms = collect_xor_terms(a);
            terms.extend(collect_xor_terms(b));
            terms
        }
        _ => vec![Rc::new(expr.clone())],
    }
}

/// Rebuild XOR expression from terms
fn rebuild_xor_from_terms(left_terms: &[Rc<ExprNode>], right_terms: &[Rc<ExprNode>]) -> ExprNode {
    let all_terms: Vec<Rc<ExprNode>> = left_terms.iter()
        .chain(right_terms.iter())
        .cloned()
        .collect();
    
    if all_terms.is_empty() {
        ExprNode::Constant(0)
    } else if all_terms.len() == 1 {
        (*all_terms[0]).clone()
    } else {
        // Build left-associative XOR chain
        let mut result = (*all_terms[0]).clone();
        for term in &all_terms[1..] {
            result = ExprNode::Xor(Rc::new(result), term.clone());
        }
        result
    }
}
