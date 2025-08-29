//! Arithmetic operation patterns

use crate::core::{
    expression::{Expr, BinOp, UnOp},
    pattern::Pattern,
    rewrite::{Rule, Rewriter},
};

/// Pattern for unsigned addition with carry
pub fn add_with_carry_pattern() -> Pattern {
    // a + b + carry
    Pattern::Binary {
        op: Some(BinOp::Add),
        left: Box::new(Pattern::Binary {
            op: Some(BinOp::Add),
            left: Box::new(Pattern::var("a")),
            right: Box::new(Pattern::var("b")),
        }),
        right: Box::new(Pattern::var("carry")),
    }
}

/// Pattern for comparison using arithmetic shift
pub fn less_than_pattern() -> Pattern {
    // (a - b) >>> 63 (sign bit extraction)
    Pattern::Unary {
        op: Some(UnOp::Sar(63)),
        pattern: Box::new(Pattern::Binary {
            op: Some(BinOp::Add), // Subtraction is addition with negation
            left: Box::new(Pattern::var("a")),
            right: Box::new(Pattern::var("b_neg")),
        }),
    }
}

/// Pattern for conditional selection (multiplexer)
pub fn mux_pattern() -> Pattern {
    // (sel & a) | ((~sel) & b)
    Pattern::Binary {
        op: Some(BinOp::Or),
        left: Box::new(Pattern::and(
            Pattern::var("sel"),
            Pattern::var("a")
        )),
        right: Box::new(Pattern::and(
            Pattern::not(Pattern::var("sel")),
            Pattern::var("b")
        )),
    }
}

/// Add arithmetic-specific rewrite rules
pub fn add_arithmetic_rules(rewriter: &mut Rewriter) {
    // Multiplexer optimization
    rewriter.add_rule(Rule::new(
        "mux-optimization",
        mux_pattern(),
        |bindings| {
            // Convert to conditional expression
            Expr::Cond {
                cond: Box::new(bindings["sel"].clone()),
                if_true: Box::new(bindings["a"].clone()),
                if_false: Box::new(bindings["b"].clone()),
            }
        }
    ));
    
    // Addition associativity for carry chains
    rewriter.add_rule(Rule::new(
        "add-reassociate",
        Pattern::Binary {
            op: Some(BinOp::Add),
            left: Box::new(Pattern::Binary {
                op: Some(BinOp::Add),
                left: Box::new(Pattern::var("a")),
                right: Box::new(Pattern::var("b")),
            }),
            right: Box::new(Pattern::var("c")),
        },
        |bindings| {
            // Reassociate for better constraint generation
            Expr::Binary {
                op: BinOp::Add,
                left: Box::new(bindings["a"].clone()),
                right: Box::new(Expr::Binary {
                    op: BinOp::Add,
                    left: Box::new(bindings["b"].clone()),
                    right: Box::new(bindings["c"].clone()),
                }),
            }
        }
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pattern::Bindings;
    
    #[test]
    fn test_mux_pattern() {
        let pattern = mux_pattern();
        
        // Create matching expression
        let expr = Expr::val(0).and(Expr::val(1))
            .or(Expr::val(0).not().and(Expr::val(2)));
        
        let mut bindings = Bindings::new();
        assert!(pattern.matches(&expr, &mut bindings));
        assert_eq!(bindings.get("sel"), Some(&Expr::val(0)));
        assert_eq!(bindings.get("a"), Some(&Expr::val(1)));
        assert_eq!(bindings.get("b"), Some(&Expr::val(2)));
    }
    
    #[test]
    fn test_add_carry_pattern() {
        let pattern = add_with_carry_pattern();
        
        // Create matching expression: (a + b) + carry
        let expr = Expr::Binary {
            op: BinOp::Add,
            left: Box::new(Expr::Binary {
                op: BinOp::Add,
                left: Box::new(Expr::val(0)),
                right: Box::new(Expr::val(1)),
            }),
            right: Box::new(Expr::val(2)),
        };
        
        let mut bindings = Bindings::new();
        assert!(pattern.matches(&expr, &mut bindings));
        assert_eq!(bindings.get("a"), Some(&Expr::val(0)));
        assert_eq!(bindings.get("b"), Some(&Expr::val(1)));
        assert_eq!(bindings.get("carry"), Some(&Expr::val(2)));
    }
}