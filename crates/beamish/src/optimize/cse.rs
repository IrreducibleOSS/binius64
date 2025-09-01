//! Common Subexpression Elimination

use crate::expr::ExprNode;
use std::collections::HashMap;
use std::rc::Rc;

/// Detect and mark common subexpressions for reuse
pub fn detect_common_subexpressions(expr: &ExprNode) -> ExprNode {
    let mut detector = CSEDetector::new();
    detector.analyze(expr);
    detector.rewrite(expr)
}

struct CSEDetector {
    /// Map from expression hash to (count, temp_id)
    expr_counts: HashMap<u64, (usize, Option<u32>)>,
    next_temp_id: u32,
}

impl CSEDetector {
    fn new() -> Self {
        Self {
            expr_counts: HashMap::new(),
            next_temp_id: 1000, // Start temp IDs at 1000 to avoid conflicts
        }
    }
    
    /// First pass: count occurrences of each subexpression
    fn analyze(&mut self, expr: &ExprNode) {
        let hash = hash_expr(expr);
        
        // Don't count trivial expressions
        if !is_trivial(expr) {
            self.expr_counts.entry(hash)
                .and_modify(|(count, _)| *count += 1)
                .or_insert((1, None));
        }
        
        // Recurse on children
        match expr {
            ExprNode::Not(inner) => self.analyze(inner),
            ExprNode::And(a, b) | ExprNode::Or(a, b) | ExprNode::Xor(a, b) => {
                self.analyze(a);
                self.analyze(b);
            }
            ExprNode::Shl(a, _) | ExprNode::Shr(a, _) | ExprNode::Sar(a, _) |
            ExprNode::Rol(a, _) | ExprNode::Ror(a, _) => {
                self.analyze(a);
            }
            ExprNode::Add32(a, b) | ExprNode::Sub32(a, b) | ExprNode::Mul32(a, b) |
            ExprNode::Add64(a, b) | ExprNode::Sub64(a, b) | ExprNode::Mul64(a, b) => {
                self.analyze(a);
                self.analyze(b);
            }
            ExprNode::Mux(cond, t, f) => {
                self.analyze(cond);
                self.analyze(t);
                self.analyze(f);
            }
            ExprNode::Equal(a, b) => {
                self.analyze(a);
                self.analyze(b);
            }
            ExprNode::BlackBox { inputs, .. } => {
                for input in inputs {
                    self.analyze(input);
                }
            }
            _ => {}
        }
    }
    
    /// Second pass: rewrite expression, replacing common subexpressions
    fn rewrite(&mut self, expr: &ExprNode) -> ExprNode {
        let hash = hash_expr(expr);
        
        // Check if this expression should be replaced with a temp
        if !is_trivial(expr) {
            if let Some((count, temp_id)) = self.expr_counts.get_mut(&hash) {
                if *count > 1 {
                    // This expression appears multiple times
                    if let Some(id) = temp_id {
                        // Already assigned a temp ID, reuse it
                        return ExprNode::Witness(*id);
                    } else {
                        // First occurrence of repeated expression
                        // Assign a temp ID but still compute it this time
                        let id = self.next_temp_id;
                        self.next_temp_id += 1;
                        *temp_id = Some(id);
                        // Continue to compute the expression
                    }
                }
            }
        }
        
        // Rewrite children
        match expr {
            ExprNode::Not(inner) => {
                ExprNode::Not(Rc::new(self.rewrite(inner)))
            }
            ExprNode::And(a, b) => {
                ExprNode::And(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Or(a, b) => {
                ExprNode::Or(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Xor(a, b) => {
                ExprNode::Xor(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Shl(a, amt) => {
                ExprNode::Shl(Rc::new(self.rewrite(a)), *amt)
            }
            ExprNode::Shr(a, amt) => {
                ExprNode::Shr(Rc::new(self.rewrite(a)), *amt)
            }
            ExprNode::Sar(a, amt) => {
                ExprNode::Sar(Rc::new(self.rewrite(a)), *amt)
            }
            ExprNode::Rol(a, amt) => {
                ExprNode::Rol(Rc::new(self.rewrite(a)), *amt)
            }
            ExprNode::Ror(a, amt) => {
                ExprNode::Ror(Rc::new(self.rewrite(a)), *amt)
            }
            ExprNode::Add32(a, b) => {
                ExprNode::Add32(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Sub32(a, b) => {
                ExprNode::Sub32(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Mul32(a, b) => {
                ExprNode::Mul32(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Add64(a, b) => {
                ExprNode::Add64(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Sub64(a, b) => {
                ExprNode::Sub64(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Mul64(a, b) => {
                ExprNode::Mul64(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::Mux(cond, t, f) => {
                ExprNode::Mux(
                    Rc::new(self.rewrite(cond)),
                    Rc::new(self.rewrite(t)),
                    Rc::new(self.rewrite(f))
                )
            }
            ExprNode::Equal(a, b) => {
                ExprNode::Equal(
                    Rc::new(self.rewrite(a)),
                    Rc::new(self.rewrite(b))
                )
            }
            ExprNode::BlackBox { compute, inputs } => {
                let new_inputs: Vec<Rc<ExprNode>> = inputs.iter()
                    .map(|input| Rc::new(self.rewrite(input)))
                    .collect();
                ExprNode::BlackBox {
                    compute: *compute,
                    inputs: new_inputs,
                }
            }
            _ => expr.clone()
        }
    }
}

/// Check if an expression is trivial (not worth CSE)
fn is_trivial(expr: &ExprNode) -> bool {
    matches!(expr, 
        ExprNode::Witness(_) | 
        ExprNode::Constant(_) |
        ExprNode::Not(_) |  // Single NOT is trivial
        ExprNode::Shl(_, _) | ExprNode::Shr(_, _) | // Shifts are trivial
        ExprNode::Sar(_, _) | ExprNode::Rol(_, _) | ExprNode::Ror(_, _)
    )
}

/// Simple hash function for expressions
fn hash_expr(expr: &ExprNode) -> u64 {
    use std::hash::Hasher;
    use std::collections::hash_map::DefaultHasher;
    
    let mut hasher = DefaultHasher::new();
    hash_expr_recursive(expr, &mut hasher);
    hasher.finish()
}

fn hash_expr_recursive<H: std::hash::Hasher>(expr: &ExprNode, hasher: &mut H) {
    use std::hash::Hash;
    
    // Hash the discriminant
    std::mem::discriminant(expr).hash(hasher);
    
    match expr {
        ExprNode::Witness(v) => v.hash(hasher),
        ExprNode::Constant(c) => c.hash(hasher),
        ExprNode::Not(inner) => hash_expr_recursive(inner, hasher),
        ExprNode::And(a, b) | ExprNode::Or(a, b) | ExprNode::Xor(a, b) => {
            hash_expr_recursive(a, hasher);
            hash_expr_recursive(b, hasher);
        }
        ExprNode::Shl(a, amt) | ExprNode::Shr(a, amt) | 
        ExprNode::Sar(a, amt) | ExprNode::Rol(a, amt) | ExprNode::Ror(a, amt) => {
            hash_expr_recursive(a, hasher);
            amt.hash(hasher);
        }
        ExprNode::Add32(a, b) | ExprNode::Sub32(a, b) | ExprNode::Mul32(a, b) |
        ExprNode::Add64(a, b) | ExprNode::Sub64(a, b) | ExprNode::Mul64(a, b) => {
            hash_expr_recursive(a, hasher);
            hash_expr_recursive(b, hasher);
        }
        ExprNode::Mux(cond, t, f) => {
            hash_expr_recursive(cond, hasher);
            hash_expr_recursive(t, hasher);
            hash_expr_recursive(f, hasher);
        }
        ExprNode::Equal(a, b) => {
            hash_expr_recursive(a, hasher);
            hash_expr_recursive(b, hasher);
        }
        ExprNode::BlackBox { compute, inputs } => {
            use std::hash::Hash;
            // Hash the function pointer
            (*compute as *const ()).hash(hasher);
            // Hash inputs
            for input in inputs {
                hash_expr_recursive(input, hasher);
            }
        }
    }
}