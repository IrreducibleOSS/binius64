//! Optimization rules for expression rewriting

use crate::expr::ExprNode;
use std::rc::Rc;

/// A rule returns Some(optimized) if it applies, None otherwise
pub type Rule = fn(&ExprNode) -> Option<Rc<ExprNode>>;

/// Result of applying a rule - includes the transformation description
pub struct RuleResult {
    pub node: Rc<ExprNode>,
    pub description: &'static str,
}

// ============================================================================
// Basic Boolean/Bitwise Rules
// ============================================================================

/// XOR with self cancels out: x ⊕ x → 0
pub fn xor_self_cancellation(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Xor(a, b) = node {
        if a == b {
            return Some(Rc::new(ExprNode::Constant(0)));
        }
    }
    None
}

/// XOR with zero is identity: x ⊕ 0 → x
pub fn xor_with_zero(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Xor(a, b) = node {
        if let ExprNode::Constant(0) = &**b {
            return Some(a.clone());
        }
        if let ExprNode::Constant(0) = &**a {
            return Some(b.clone());
        }
    }
    None
}

/// XOR with all-ones is NOT: x ⊕ 1* → ¬x
pub fn xor_with_ones(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Xor(a, b) = node {
        if let ExprNode::Constant(0xFFFFFFFFFFFFFFFF) = &**b {
            return Some(Rc::new(ExprNode::Not(a.clone())));
        }
        if let ExprNode::Constant(0xFFFFFFFFFFFFFFFF) = &**a {
            return Some(Rc::new(ExprNode::Not(b.clone())));
        }
    }
    None
}

/// Double NOT cancels: ¬¬x → x
pub fn double_not_elimination(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Not(inner) = node {
        if let ExprNode::Not(inner2) = &**inner {
            return Some(inner2.clone());
        }
    }
    None
}

/// NOT of constants: ¬0 → 1*, ¬1* → 0
pub fn not_constant_folding(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Not(inner) = node {
        if let ExprNode::Constant(0) = &**inner {
            return Some(Rc::new(ExprNode::Constant(0xFFFFFFFFFFFFFFFF)));
        }
        if let ExprNode::Constant(0xFFFFFFFFFFFFFFFF) = &**inner {
            return Some(Rc::new(ExprNode::Constant(0)));
        }
    }
    None
}

/// AND with self is identity: x ∧ x → x
pub fn and_self_identity(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::And(a, b) = node {
        if a == b {
            return Some(a.clone());
        }
    }
    None
}

/// AND with zero is zero: x ∧ 0 → 0
pub fn and_with_zero(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::And(a, b) = node {
        if let ExprNode::Constant(0) = &**a {
            return Some(Rc::new(ExprNode::Constant(0)));
        }
        if let ExprNode::Constant(0) = &**b {
            return Some(Rc::new(ExprNode::Constant(0)));
        }
    }
    None
}

/// AND with all-ones is identity: x ∧ 1* → x
pub fn and_with_ones(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::And(a, b) = node {
        if let ExprNode::Constant(0xFFFFFFFFFFFFFFFF) = &**a {
            return Some(b.clone());
        }
        if let ExprNode::Constant(0xFFFFFFFFFFFFFFFF) = &**b {
            return Some(a.clone());
        }
    }
    None
}

/// OR with self is identity: x ∨ x → x
pub fn or_self_identity(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Or(a, b) = node {
        if a == b {
            return Some(a.clone());
        }
    }
    None
}

/// OR with zero is identity: x ∨ 0 → x
pub fn or_with_zero(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Or(a, b) = node {
        if let ExprNode::Constant(0) = &**a {
            return Some(b.clone());
        }
        if let ExprNode::Constant(0) = &**b {
            return Some(a.clone());
        }
    }
    None
}

/// OR with all-ones is all-ones: x ∨ 1* → 1*
pub fn or_with_ones(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Or(a, b) = node {
        if let ExprNode::Constant(0xFFFFFFFFFFFFFFFF) = &**a {
            return Some(Rc::new(ExprNode::Constant(0xFFFFFFFFFFFFFFFF)));
        }
        if let ExprNode::Constant(0xFFFFFFFFFFFFFFFF) = &**b {
            return Some(Rc::new(ExprNode::Constant(0xFFFFFFFFFFFFFFFF)));
        }
    }
    None
}

// ============================================================================
// Advanced Pattern Rules (TODO)
// ============================================================================

/// Pass 1: XOR Chain Consolidation
/// Pattern: (a ⊕ b) ⊕ (a ⊕ c) → b ⊕ c
/// Eliminates common terms in nested XOR operations
pub fn xor_chain_rule(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Xor(left, right) = node {
        // Check if both sides are XOR operations
        if let (ExprNode::Xor(a1, b1), ExprNode::Xor(a2, b2)) = (&**left, &**right) {
            // Check for common terms and eliminate them
            // Case 1: (a ⊕ b) ⊕ (a ⊕ c) → b ⊕ c
            if a1 == a2 {
                return Some(Rc::new(ExprNode::Xor(b1.clone(), b2.clone())));
            }
            // Case 2: (a ⊕ b) ⊕ (c ⊕ a) → b ⊕ c
            if a1 == b2 {
                return Some(Rc::new(ExprNode::Xor(b1.clone(), a2.clone())));
            }
            // Case 3: (b ⊕ a) ⊕ (a ⊕ c) → b ⊕ c
            if b1 == a2 {
                return Some(Rc::new(ExprNode::Xor(a1.clone(), b2.clone())));
            }
            // Case 4: (b ⊕ a) ⊕ (c ⊕ a) → b ⊕ c
            if b1 == b2 {
                return Some(Rc::new(ExprNode::Xor(a1.clone(), a2.clone())));
            }
        }
    }
    None
}

/// Pass 2: Masked AND-XOR Pattern
/// Pattern: a ⊕ ((¬b) ∧ c) → optimized form
/// Common pattern in cryptographic algorithms (e.g., chi step)
/// Reduces 3 constraints to 1 specialized constraint
pub fn masked_and_xor_rule(node: &ExprNode) -> Option<Rc<ExprNode>> {
    if let ExprNode::Xor(a, right) = node {
        // Check for (¬b) ∧ c pattern
        if let ExprNode::And(left_and, c) = &**right {
            if let ExprNode::Not(b) = &**left_and {
                // Found the masked AND-XOR pattern: a ⊕ ((¬b) ∧ c)
                // This pattern is optimized during constraint generation in constraints.rs
                // The Equal handler recognizes this pattern and generates a single optimized constraint
                log::debug!("PATTERN: Masked AND-XOR detected (optimization happens in constraint generation)");
                return None;
            }
        }
        // Also check reverse: ((¬b) ∧ c) ⊕ a
        if let ExprNode::And(left_and, c) = &**a {
            if let ExprNode::Not(b) = &**left_and {
                // Found the pattern ((¬b) ∧ c) ⊕ a → a ⊕ ((¬b) ∧ c)
                // Normalize to standard form
                return Some(Rc::new(ExprNode::Xor(right.clone(), a.clone())));
            }
        }
    }
    None
}

/// Pass 3: Rotation-XOR Elimination
/// Pattern: (x >>> a) ⊕ (x >>> b) ⊕ (x >>> c) → optimized form
/// Combines multiple rotations of the same value
/// Eliminates intermediate constraints in rotation-heavy algorithms
pub fn rotation_xor_rule(node: &ExprNode) -> Option<Rc<ExprNode>> {
    // Check for XOR of rotations
    if let ExprNode::Xor(left, right) = node {
        // Check if we have rotation ⊕ rotation
        let is_rotation = |n: &ExprNode| matches!(n, 
            ExprNode::Rol(_, _) | ExprNode::Ror(_, _) | 
            ExprNode::Shl(_, _) | ExprNode::Shr(_, _) | ExprNode::Sar(_, _)
        );
        
        // Extract base value from rotation
        let get_base = |n: &ExprNode| -> Option<Rc<ExprNode>> {
            match n {
                ExprNode::Rol(base, _) | ExprNode::Ror(base, _) |
                ExprNode::Shl(base, _) | ExprNode::Shr(base, _) | 
                ExprNode::Sar(base, _) => Some(base.clone()),
                _ => None
            }
        };
        
        // Check for pattern: (x >>> a) ⊕ (x >>> b)
        if is_rotation(left) && is_rotation(right) {
            if let (Some(base1), Some(base2)) = (get_base(left), get_base(right)) {
                if base1 == base2 {
                    // Found rotation-XOR pattern with same base
                    // Already optimal in our constraint system - rotations compile to ShiftedValues
                    log::debug!("PATTERN: Rotation-XOR detected (already optimal via ShiftedValues)");
                    return None;
                }
            }
        }
        
        // Check for nested: ((x >>> a) ⊕ (x >>> b)) ⊕ (x >>> c)
        if let ExprNode::Xor(left_left, left_right) = &**left {
            if is_rotation(left_left) && is_rotation(left_right) && is_rotation(right) {
                if let (Some(base1), Some(base2), Some(base3)) = 
                    (get_base(left_left), get_base(left_right), get_base(right)) {
                    if base1 == base2 && base2 == base3 {
                        // Found triple rotation-XOR pattern
                        // Common in cryptographic mixing functions
                        log::debug!("PATTERN: Triple Rotation-XOR detected (already optimal via ShiftedValues)");
                        return None;
                    }
                }
            }
        }
    }
    None
}

// ============================================================================
// Rule Registry
// ============================================================================

/// Get all basic optimization rules
pub fn basic_rules() -> Vec<(&'static str, Rule)> {
    vec![
        ("XOR(x,x) → 0", xor_self_cancellation),
        ("XOR(x,0) → x", xor_with_zero),
        ("XOR(x,1*) → ¬x", xor_with_ones),
        ("NOT(NOT(x)) → x", double_not_elimination),
        ("NOT(const) → folded", not_constant_folding),
        ("AND(x,x) → x", and_self_identity),
        ("AND(x,0) → 0", and_with_zero),
        ("AND(x,1*) → x", and_with_ones),
        ("OR(x,x) → x", or_self_identity),
        ("OR(x,0) → x", or_with_zero),
        ("OR(x,1*) → 1*", or_with_ones),
    ]
}

/// Get all advanced pattern rules
pub fn advanced_rules() -> Vec<(&'static str, Rule)> {
    vec![
        ("XOR chain consolidation", xor_chain_rule),
        ("Masked AND-XOR pattern", masked_and_xor_rule),
        ("Rotation-XOR elimination", rotation_xor_rule),
    ]
}

/// Get all enabled rules based on configuration
pub fn get_enabled_rules(config: &crate::optimize::OptimizationConfig) -> Vec<(&'static str, Rule)> {
    let mut rules = Vec::new();
    
    // Add basic rules based on config
    if config.xor_self_cancellation {
        rules.push(("XOR(x,x) → 0", xor_self_cancellation as Rule));
    }
    if config.xor_with_zero {
        rules.push(("XOR(x,0) → x", xor_with_zero as Rule));
    }
    if config.xor_with_ones {
        rules.push(("XOR(x,1*) → ¬x", xor_with_ones as Rule));
    }
    if config.double_not_elimination {
        rules.push(("NOT(NOT(x)) → x", double_not_elimination as Rule));
    }
    if config.not_constant_folding {
        rules.push(("NOT(const) → folded", not_constant_folding as Rule));
    }
    if config.and_self_identity {
        rules.push(("AND(x,x) → x", and_self_identity as Rule));
    }
    if config.and_with_zero {
        rules.push(("AND(x,0) → 0", and_with_zero as Rule));
    }
    if config.and_with_ones {
        rules.push(("AND(x,1*) → x", and_with_ones as Rule));
    }
    if config.or_self_identity {
        rules.push(("OR(x,x) → x", or_self_identity as Rule));
    }
    if config.or_with_zero {
        rules.push(("OR(x,0) → x", or_with_zero as Rule));
    }
    if config.or_with_ones {
        rules.push(("OR(x,1*) → 1*", or_with_ones as Rule));
    }
    
    // Add advanced rules based on config
    if config.xor_chain_consolidation {
        rules.push(("XOR chain consolidation", xor_chain_rule as Rule));
    }
    
    // Note: masked_and_xor and rotation_xor are handled at constraint generation level
    // We still detect them for logging but don't transform
    
    rules
}

/// Get all enabled rules (legacy - uses default config)
pub fn all_rules() -> Vec<(&'static str, Rule)> {
    get_enabled_rules(&crate::optimize::OptimizationConfig::default())
}