//! Pattern matching for expression rewriting

use super::expression::{Expr, BinOp, UnOp};

/// Pattern for matching expressions
#[derive(Clone, Debug)]
pub enum Pattern {
    /// Match any expression and bind it to a variable
    Var(String),
    
    /// Match a constant value
    Const(Option<u64>),
    
    /// Match a value reference  
    Value,
    
    /// Match a binary operation
    Binary {
        op: Option<BinOp>,
        left: Box<Pattern>,
        right: Box<Pattern>,
    },
    
    /// Match a unary operation
    Unary {
        op: Option<UnOp>,
        pattern: Box<Pattern>,
    },
    
    /// Match XOR chain with multiple terms
    XorChain(Vec<Pattern>),
    
    /// Match NOT of a pattern
    Not(Box<Pattern>),
}

/// Bindings from pattern variables to expressions
pub type Bindings = std::collections::HashMap<String, Expr>;

impl Pattern {
    /// Try to match this pattern against an expression
    pub fn matches(&self, expr: &Expr, bindings: &mut Bindings) -> bool {
        match (self, expr) {
            // Variable always matches and binds
            (Pattern::Var(name), _) => {
                if let Some(bound) = bindings.get(name) {
                    // Check if already bound to same expression
                    bound == expr
                } else {
                    // Bind the variable
                    bindings.insert(name.clone(), expr.clone());
                    true
                }
            }
            
            // Constants
            (Pattern::Const(None), Expr::Const(_)) => true,
            (Pattern::Const(Some(val)), Expr::Const(c)) => val == c,
            
            // Values
            (Pattern::Value, Expr::Value(_)) => true,
            
            // Binary operations
            (Pattern::Binary { op, left, right }, 
             Expr::Binary { op: expr_op, left: expr_left, right: expr_right }) => {
                // Check operation if specified
                if let Some(pattern_op) = op
                    && pattern_op != expr_op {
                        return false;
                    }
                // Match operands
                left.matches(expr_left, bindings) && right.matches(expr_right, bindings)
            }
            
            // Unary operations
            (Pattern::Unary { op, pattern },
             Expr::Unary { op: expr_op, expr }) => {
                // Check operation if specified
                if let Some(pattern_op) = op
                    && pattern_op != expr_op {
                        return false;
                    }
                pattern.matches(expr, bindings)
            }
            
            // NOT pattern
            (Pattern::Not(pattern), Expr::Unary { op: UnOp::Not, expr }) => {
                pattern.matches(expr, bindings)
            }
            
            // XOR chain matching
            (Pattern::XorChain(patterns), expr) => {
                self.match_xor_chain(patterns, expr, bindings)
            }
            
            _ => false,
        }
    }
    
    /// Match an XOR chain pattern
    fn match_xor_chain(&self, patterns: &[Pattern], expr: &Expr, bindings: &mut Bindings) -> bool {
        // Collect all XOR terms from the expression
        let mut terms = Vec::new();
        self.collect_xor_terms(expr, &mut terms);
        
        // Try to match patterns to terms
        if patterns.len() != terms.len() {
            return false;
        }
        
        // For now, simple ordered matching (could be improved)
        for (pattern, term) in patterns.iter().zip(terms.iter()) {
            if !pattern.matches(term, bindings) {
                return false;
            }
        }
        
        true
    }
    
    /// Collect all terms in an XOR expression
    #[allow(clippy::only_used_in_recursion)]
    fn collect_xor_terms<'a>(&self, expr: &'a Expr, terms: &mut Vec<&'a Expr>) {
        match expr {
            Expr::Binary { op: BinOp::Xor, left, right } => {
                self.collect_xor_terms(left, terms);
                self.collect_xor_terms(right, terms);
            }
            _ => terms.push(expr),
        }
    }
}

/// Pattern builder helpers
impl Pattern {
    pub fn var(name: impl Into<String>) -> Self {
        Pattern::Var(name.into())
    }
    
    pub fn constant(value: u64) -> Self {
        Pattern::Const(Some(value))
    }
    
    pub fn any_const() -> Self {
        Pattern::Const(None)
    }
    
    pub fn value() -> Self {
        Pattern::Value
    }
    
    pub fn xor(left: Pattern, right: Pattern) -> Self {
        Pattern::Binary {
            op: Some(BinOp::Xor),
            left: Box::new(left),
            right: Box::new(right),
        }
    }
    
    pub fn and(left: Pattern, right: Pattern) -> Self {
        Pattern::Binary {
            op: Some(BinOp::And),
            left: Box::new(left),
            right: Box::new(right),
        }
    }
    
    #[allow(clippy::should_implement_trait)]
    pub fn not(pattern: Pattern) -> Self {
        Pattern::Not(Box::new(pattern))
    }
    
    pub fn xor_chain(patterns: Vec<Pattern>) -> Self {
        Pattern::XorChain(patterns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::expression::Expr;
    
    #[test]
    fn test_pattern_matching() {
        // Test Keccak chi pattern: a ^ ((~b) & c)
        let chi_pattern = Pattern::xor(
            Pattern::var("a"),
            Pattern::and(
                Pattern::not(Pattern::var("b")),
                Pattern::var("c")
            )
        );
        
        // Create a matching expression
        let expr = Expr::val(0).xor(
            Expr::val(1).not().and(Expr::val(2))
        );
        
        let mut bindings = Bindings::new();
        assert!(chi_pattern.matches(&expr, &mut bindings));
        
        // Check bindings
        assert_eq!(bindings.get("a"), Some(&Expr::val(0)));
        assert_eq!(bindings.get("b"), Some(&Expr::val(1)));
        assert_eq!(bindings.get("c"), Some(&Expr::val(2)));
    }
    
    #[test]
    fn test_xor_chain_matching() {
        // Pattern for XOR chain
        let pattern = Pattern::xor_chain(vec![
            Pattern::var("a"),
            Pattern::var("b"),
            Pattern::var("c"),
        ]);
        
        // Create matching expression
        let expr = Expr::val(0)
            .xor(Expr::val(1))
            .xor(Expr::val(2));
        
        let mut bindings = Bindings::new();
        assert!(pattern.matches(&expr, &mut bindings));
        
        assert_eq!(bindings.get("a"), Some(&Expr::val(0)));
        assert_eq!(bindings.get("b"), Some(&Expr::val(1)));
        assert_eq!(bindings.get("c"), Some(&Expr::val(2)));
    }
}