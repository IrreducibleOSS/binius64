//! Expression canonicalization for robust pattern matching

use crate::expr::ExprNode;
use std::rc::Rc;
use std::cmp::Ordering;

/// Canonicalize an expression for consistent pattern matching
/// - Sorts commutative operations (AND, OR, XOR)
/// - Flattens associative operations
/// - Normalizes equivalent representations
pub fn canonicalize(expr: &ExprNode) -> ExprNode {
    match expr {
        // Commutative binary operations - sort operands
        ExprNode::And(a, b) => {
            let a_canon = Rc::new(canonicalize(a));
            let b_canon = Rc::new(canonicalize(b));
            if compare_expr(&a_canon, &b_canon) == Ordering::Greater {
                ExprNode::And(b_canon, a_canon)
            } else {
                ExprNode::And(a_canon, b_canon)
            }
        }
        
        ExprNode::Or(a, b) => {
            let a_canon = Rc::new(canonicalize(a));
            let b_canon = Rc::new(canonicalize(b));
            if compare_expr(&a_canon, &b_canon) == Ordering::Greater {
                ExprNode::Or(b_canon, a_canon)
            } else {
                ExprNode::Or(a_canon, b_canon)
            }
        }
        
        ExprNode::Xor(a, b) => {
            let a_canon = Rc::new(canonicalize(a));
            let b_canon = Rc::new(canonicalize(b));
            if compare_expr(&a_canon, &b_canon) == Ordering::Greater {
                ExprNode::Xor(b_canon, a_canon)
            } else {
                ExprNode::Xor(a_canon, b_canon)
            }
        }
        
        // Arithmetic operations - sort for consistency
        ExprNode::Add32(a, b) | ExprNode::Add64(a, b) => {
            let a_canon = Rc::new(canonicalize(a));
            let b_canon = Rc::new(canonicalize(b));
            if compare_expr(&a_canon, &b_canon) == Ordering::Greater {
                match expr {
                    ExprNode::Add32(_, _) => ExprNode::Add32(b_canon, a_canon),
                    ExprNode::Add64(_, _) => ExprNode::Add64(b_canon, a_canon),
                    _ => unreachable!(),
                }
            } else {
                match expr {
                    ExprNode::Add32(_, _) => ExprNode::Add32(a_canon, b_canon),
                    ExprNode::Add64(_, _) => ExprNode::Add64(a_canon, b_canon),
                    _ => unreachable!(),
                }
            }
        }
        
        ExprNode::Mul32(a, b) | ExprNode::Mul64(a, b) => {
            let a_canon = Rc::new(canonicalize(a));
            let b_canon = Rc::new(canonicalize(b));
            if compare_expr(&a_canon, &b_canon) == Ordering::Greater {
                match expr {
                    ExprNode::Mul32(_, _) => ExprNode::Mul32(b_canon, a_canon),
                    ExprNode::Mul64(_, _) => ExprNode::Mul64(b_canon, a_canon),
                    _ => unreachable!(),
                }
            } else {
                match expr {
                    ExprNode::Mul32(_, _) => ExprNode::Mul32(a_canon, b_canon),
                    ExprNode::Mul64(_, _) => ExprNode::Mul64(a_canon, b_canon),
                    _ => unreachable!(),
                }
            }
        }
        
        // Recursively canonicalize unary operations
        ExprNode::Not(inner) => {
            ExprNode::Not(Rc::new(canonicalize(inner)))
        }
        
        ExprNode::Shl(inner, amt) => {
            ExprNode::Shl(Rc::new(canonicalize(inner)), *amt)
        }
        
        ExprNode::Shr(inner, amt) => {
            ExprNode::Shr(Rc::new(canonicalize(inner)), *amt)
        }
        
        ExprNode::Sar(inner, amt) => {
            ExprNode::Sar(Rc::new(canonicalize(inner)), *amt)
        }
        
        ExprNode::Rol(inner, amt) => {
            ExprNode::Rol(Rc::new(canonicalize(inner)), *amt)
        }
        
        ExprNode::Ror(inner, amt) => {
            ExprNode::Ror(Rc::new(canonicalize(inner)), *amt)
        }
        
        // Non-commutative operations and leaves
        ExprNode::Sub32(a, b) => {
            ExprNode::Sub32(Rc::new(canonicalize(a)), Rc::new(canonicalize(b)))
        }
        
        ExprNode::Sub64(a, b) => {
            ExprNode::Sub64(Rc::new(canonicalize(a)), Rc::new(canonicalize(b)))
        }
        
        ExprNode::Mux(cond, t, f) => {
            ExprNode::Mux(
                Rc::new(canonicalize(cond)),
                Rc::new(canonicalize(t)),
                Rc::new(canonicalize(f))
            )
        }
        
        ExprNode::Equal(a, b) => {
            let a_canon = Rc::new(canonicalize(a));
            let b_canon = Rc::new(canonicalize(b));
            // Sort for consistency
            if compare_expr(&a_canon, &b_canon) == Ordering::Greater {
                ExprNode::Equal(b_canon, a_canon)
            } else {
                ExprNode::Equal(a_canon, b_canon)
            }
        }
        
        // Leaves unchanged
        ExprNode::Witness(_) | ExprNode::Constant(_) => expr.clone(),
        
        ExprNode::BlackBox { compute, inputs } => {
            // Canonicalize inputs
            let canonical_inputs: Vec<Rc<ExprNode>> = inputs.iter()
                .map(|input| Rc::new(canonicalize(input)))
                .collect();
            ExprNode::BlackBox {
                compute: *compute,
                inputs: canonical_inputs,
            }
        }
    }
}

/// Compare expressions for consistent ordering
fn compare_expr(a: &ExprNode, b: &ExprNode) -> Ordering {
    use ExprNode::*;
    
    // Order by type first
    match (a, b) {
        (Constant(x), Constant(y)) => x.cmp(y),
        (Witness(x), Witness(y)) => x.cmp(y),
        
        // Constants come first
        (Constant(_), _) => Ordering::Less,
        (_, Constant(_)) => Ordering::Greater,
        
        // Then witnesses
        (Witness(_), _) => Ordering::Less,
        (_, Witness(_)) => Ordering::Greater,
        
        // For operations, compare recursively
        (Not(x), Not(y)) => compare_expr(x, y),
        
        (And(a1, b1), And(a2, b2)) |
        (Or(a1, b1), Or(a2, b2)) |
        (Xor(a1, b1), Xor(a2, b2)) => {
            match compare_expr(a1, a2) {
                Ordering::Equal => compare_expr(b1, b2),
                other => other,
            }
        }
        
        // Different operation types - use discriminant ordering
        _ => {
            let disc_a = expr_discriminant(a);
            let disc_b = expr_discriminant(b);
            disc_a.cmp(&disc_b)
        }
    }
}

/// Get a discriminant for expression type ordering
fn expr_discriminant(expr: &ExprNode) -> u8 {
    use ExprNode::*;
    match expr {
        Constant(_) => 0,
        Witness(_) => 1,
        Not(_) => 2,
        And(_, _) => 3,
        Or(_, _) => 4,
        Xor(_, _) => 5,
        Shl(_, _) => 6,
        Shr(_, _) => 7,
        Sar(_, _) => 8,
        Rol(_, _) => 9,
        Ror(_, _) => 10,
        Add32(_, _) => 11,
        Add64(_, _) => 12,
        Sub32(_, _) => 13,
        Sub64(_, _) => 14,
        Mul32(_, _) => 15,
        Mul64(_, _) => 16,
        Mux(_, _, _) => 17,
        Equal(_, _) => 18,
        BlackBox { .. } => 19,
    }
}

/// Flatten nested associative operations (XOR, AND, OR)
pub fn flatten_associative(expr: &ExprNode) -> Vec<Rc<ExprNode>> {
    match expr {
        ExprNode::Xor(a, b) => {
            let mut terms = flatten_associative(a);
            terms.extend(flatten_associative(b));
            terms
        }
        ExprNode::And(a, b) => {
            let mut terms = flatten_associative(a);
            terms.extend(flatten_associative(b));
            terms
        }
        ExprNode::Or(a, b) => {
            let mut terms = flatten_associative(a);
            terms.extend(flatten_associative(b));
            terms
        }
        _ => vec![Rc::new(expr.clone())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::ExprNode;
    
    #[test]
    fn test_canonicalize_sorts_operands() {
        // Create b & a
        let a = ExprNode::Witness(1);
        let b = ExprNode::Witness(2);
        let expr = ExprNode::And(Rc::new(b.clone()), Rc::new(a.clone()));
        
        // Should become a & b
        let canon = canonicalize(&expr);
        match canon {
            ExprNode::And(ref left, ref right) => {
                assert_eq!(left.as_ref(), &a);
                assert_eq!(right.as_ref(), &b);
            }
            _ => panic!("Expected And"),
        }
    }
    
    #[test]
    fn test_flatten_xor_chain() {
        // Create (a ⊕ b) ⊕ c
        let a = ExprNode::Witness(1);
        let b = ExprNode::Witness(2);
        let c = ExprNode::Witness(3);
        
        let ab = ExprNode::Xor(Rc::new(a.clone()), Rc::new(b.clone()));
        let abc = ExprNode::Xor(Rc::new(ab), Rc::new(c.clone()));
        
        let flattened = flatten_associative(&abc);
        assert_eq!(flattened.len(), 3);
    }
}