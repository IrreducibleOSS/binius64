//! Expression rewriting engine

use super::expression::Expr;
use super::pattern::{Pattern, Bindings};

/// A rewrite rule transforms expressions matching a pattern
pub struct Rule {
    pub name: String,
    pub pattern: Pattern,
    pub transform: Box<dyn Fn(&Bindings) -> Expr>,
}

impl Rule {
    pub fn new(
        name: impl Into<String>,
        pattern: Pattern,
        transform: impl Fn(&Bindings) -> Expr + 'static,
    ) -> Self {
        Rule {
            name: name.into(),
            pattern,
            transform: Box::new(transform),
        }
    }
    
    /// Try to apply this rule to an expression
    pub fn apply(&self, expr: &Expr) -> Option<Expr> {
        let mut bindings = Bindings::new();
        if self.pattern.matches(expr, &mut bindings) {
            Some((self.transform)(&bindings))
        } else {
            None
        }
    }
}

/// Collection of rewrite rules
#[derive(Default)]
pub struct Rewriter {
    rules: Vec<Rule>,
}

impl Rewriter {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }
    
    /// Apply rules to an expression until fixed point
    pub fn rewrite(&self, expr: &Expr) -> Expr {
        let mut current = expr.clone();
        let mut changed = true;
        
        while changed {
            changed = false;
            
            // Try each rule
            for rule in &self.rules {
                if let Some(rewritten) = self.apply_rule_recursive(rule, &current) {
                    current = rewritten;
                    changed = true;
                    break; // Start over with new expression
                }
            }
        }
        
        current
    }
    
    /// Apply a rule recursively through the expression tree
    #[allow(clippy::only_used_in_recursion)]
    fn apply_rule_recursive(&self, rule: &Rule, expr: &Expr) -> Option<Expr> {
        // First try to apply at root
        if let Some(result) = rule.apply(expr) {
            return Some(result);
        }
        
        // Then try to apply to subexpressions
        match expr {
            Expr::Binary { op, left, right } => {
                let new_left = self.apply_rule_recursive(rule, left)
                    .map(Box::new)
                    .unwrap_or_else(|| left.clone());
                let new_right = self.apply_rule_recursive(rule, right)
                    .map(Box::new)
                    .unwrap_or_else(|| right.clone());
                
                if &new_left != left || &new_right != right {
                    Some(Expr::Binary {
                        op: *op,
                        left: new_left,
                        right: new_right,
                    })
                } else {
                    None
                }
            }
            Expr::Unary { op, expr: inner } => {
                self.apply_rule_recursive(rule, inner).map(|new_inner| {
                    Expr::Unary {
                        op: *op,
                        expr: Box::new(new_inner),
                    }
                })
            }
            Expr::Cond { cond, if_true, if_false } => {
                let new_cond = self.apply_rule_recursive(rule, cond)
                    .map(Box::new)
                    .unwrap_or_else(|| cond.clone());
                let new_true = self.apply_rule_recursive(rule, if_true)
                    .map(Box::new)
                    .unwrap_or_else(|| if_true.clone());
                let new_false = self.apply_rule_recursive(rule, if_false)
                    .map(Box::new)
                    .unwrap_or_else(|| if_false.clone());
                
                if &new_cond != cond || &new_true != if_true || &new_false != if_false {
                    Some(Expr::Cond {
                        cond: new_cond,
                        if_true: new_true,
                        if_false: new_false,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Standard rewrite rules for optimization
impl Rewriter {
    pub fn with_standard_rules() -> Self {
        let mut rewriter = Rewriter::new();
        
        // XOR with self = 0
        rewriter.add_rule(Rule::new(
            "xor-self-elimination",
            Pattern::xor(Pattern::var("a"), Pattern::var("a")),
            |_| Expr::constant(0),
        ));
        
        // XOR with 0 = identity
        rewriter.add_rule(Rule::new(
            "xor-zero-identity",
            Pattern::xor(Pattern::var("a"), Pattern::constant(0)),
            |bindings| bindings["a"].clone(),
        ));
        
        // Double NOT = identity
        rewriter.add_rule(Rule::new(
            "double-not-elimination",
            Pattern::not(Pattern::not(Pattern::var("a"))),
            |bindings| bindings["a"].clone(),
        ));
        
        // AND with 0 = 0
        rewriter.add_rule(Rule::new(
            "and-zero-annihilation",
            Pattern::and(Pattern::var("a"), Pattern::constant(0)),
            |_| Expr::constant(0),
        ));
        
        // AND with all 1s = identity
        rewriter.add_rule(Rule::new(
            "and-ones-identity",
            Pattern::and(Pattern::var("a"), Pattern::constant(0xFFFFFFFFFFFFFFFF)),
            |bindings| bindings["a"].clone(),
        ));
        
        rewriter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_xor_elimination() {
        let rewriter = Rewriter::with_standard_rules();
        
        // a ^ a = 0
        let expr = Expr::val(0).xor(Expr::val(0));
        let result = rewriter.rewrite(&expr);
        assert_eq!(result, Expr::constant(0));
        
        // a ^ 0 = a
        let expr = Expr::val(0).xor(Expr::constant(0));
        let result = rewriter.rewrite(&expr);
        assert_eq!(result, Expr::val(0));
    }
    
    #[test]
    fn test_not_elimination() {
        let rewriter = Rewriter::with_standard_rules();
        
        // ~~a = a
        let expr = Expr::val(0).not().not();
        let result = rewriter.rewrite(&expr);
        assert_eq!(result, Expr::val(0));
    }
    
    #[test]
    fn test_and_simplification() {
        let rewriter = Rewriter::with_standard_rules();
        
        // a & 0 = 0
        let expr = Expr::val(0).and(Expr::constant(0));
        let result = rewriter.rewrite(&expr);
        assert_eq!(result, Expr::constant(0));
        
        // a & 0xFFFF... = a
        let expr = Expr::val(0).and(Expr::constant(0xFFFFFFFFFFFFFFFF));
        let result = rewriter.rewrite(&expr);
        assert_eq!(result, Expr::val(0));
    }
}