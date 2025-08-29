//! Cryptographic operation patterns

use crate::core::{
    expression::{Expr, BinOp, UnOp},
    pattern::Pattern,
    rewrite::{Rule, Rewriter},
};

/// Keccak chi pattern: a ^ ((~b) & c)
pub fn keccak_chi_pattern() -> Pattern {
    Pattern::xor(
        Pattern::var("a"),
        Pattern::and(
            Pattern::not(Pattern::var("b")),
            Pattern::var("c")
        )
    )
}

/// SHA256 Sigma patterns
pub fn sha_sigma_pattern() -> Pattern {
    // (x >>> a) ^ (x >>> b) ^ (x >>> c)
    Pattern::xor_chain(vec![
        Pattern::Unary {
            op: Some(UnOp::Ror(0)), // Will be matched with actual rotation amounts
            pattern: Box::new(Pattern::var("x")),
        },
        Pattern::Unary {
            op: Some(UnOp::Ror(0)),
            pattern: Box::new(Pattern::var("x")),
        },
        Pattern::Unary {
            op: Some(UnOp::Ror(0)),
            pattern: Box::new(Pattern::var("x")),
        },
    ])
}

/// SHA256 Ch function: (a & b) ^ ((~a) & c)
pub fn sha_ch_pattern() -> Pattern {
    Pattern::xor(
        Pattern::and(Pattern::var("a"), Pattern::var("b")),
        Pattern::and(
            Pattern::not(Pattern::var("a")),
            Pattern::var("c")
        )
    )
}

/// SHA256 Maj function: (a & b) ^ (a & c) ^ (b & c)
pub fn sha_maj_pattern() -> Pattern {
    Pattern::xor_chain(vec![
        Pattern::and(Pattern::var("a"), Pattern::var("b")),
        Pattern::and(Pattern::var("a"), Pattern::var("c")),
        Pattern::and(Pattern::var("b"), Pattern::var("c")),
    ])
}

/// Add crypto-specific rewrite rules
pub fn add_crypto_rules(rewriter: &mut Rewriter) {
    // Keccak chi optimization
    rewriter.add_rule(Rule::new(
        "keccak-chi-optimization",
        keccak_chi_pattern(),
        |bindings| {
            // This would be optimized to a single AND constraint
            // For now, return a marked expression
            Expr::Binary {
                op: BinOp::Xor,
                left: Box::new(bindings["a"].clone()),
                right: Box::new(Expr::Binary {
                    op: BinOp::And,
                    left: Box::new(Expr::Unary {
                        op: UnOp::Not,
                        expr: Box::new(bindings["b"].clone()),
                    }),
                    right: Box::new(bindings["c"].clone()),
                }),
            }
        }
    ));
    
    // SHA Ch optimization
    rewriter.add_rule(Rule::new(
        "sha-ch-optimization", 
        sha_ch_pattern(),
        |bindings| {
            // Optimized form using conditional
            Expr::Cond {
                cond: Box::new(bindings["a"].clone()),
                if_true: Box::new(bindings["b"].clone()),
                if_false: Box::new(bindings["c"].clone()),
            }
        }
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pattern::Bindings;
    
    #[test]
    fn test_keccak_chi_pattern() {
        let pattern = keccak_chi_pattern();
        
        // Create matching expression
        let expr = Expr::val(0).xor(
            Expr::val(1).not().and(Expr::val(2))
        );
        
        let mut bindings = Bindings::new();
        assert!(pattern.matches(&expr, &mut bindings));
        assert_eq!(bindings.get("a"), Some(&Expr::val(0)));
        assert_eq!(bindings.get("b"), Some(&Expr::val(1)));
        assert_eq!(bindings.get("c"), Some(&Expr::val(2)));
    }
    
    #[test]
    fn test_sha_ch_pattern() {
        let pattern = sha_ch_pattern();
        
        // Create matching expression
        let expr = Expr::val(0).and(Expr::val(1))
            .xor(Expr::val(0).not().and(Expr::val(2)));
        
        let mut bindings = Bindings::new();
        assert!(pattern.matches(&expr, &mut bindings));
        assert_eq!(bindings.get("a"), Some(&Expr::val(0)));
        assert_eq!(bindings.get("b"), Some(&Expr::val(1)));
        assert_eq!(bindings.get("c"), Some(&Expr::val(2)));
    }
}