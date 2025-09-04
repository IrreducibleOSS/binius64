//! Expression trees for verification predicates

use crate::witness::WitnessVar;

/// An expression tree representing a computation
/// These are NESTABLE trees used for constraint optimization/packing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// A witness variable
    Var(WitnessVar),
    
    /// XOR of two expressions (free operation, nestable)
    Xor(Box<Expression>, Box<Expression>),
    
    /// AND of two expressions (generates constraint, nestable)
    And(Box<Expression>, Box<Expression>),
    
    /// NOT of an expression (free - XOR with all-1s)
    Not(Box<Expression>),
    
    /// Bit shift operation (free operation)
    Shift {
        input: Box<Expression>,
        variant: ShiftVariant,
        amount: u8,
    },
    
    /// Multiplication (generates constraint)
    /// Note: MUL produces TWO outputs (hi, lo), handled specially in predicates
    Mul(Box<Expression>, Box<Expression>),
}

/// Shift operation variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftVariant {
    /// Logical left shift
    Sll,
    /// Logical right shift
    Slr,
    /// Arithmetic right shift
    Sar,
}

impl Expression {
    /// Create a variable expression
    pub fn var(v: WitnessVar) -> Self {
        Expression::Var(v)
    }
    
    /// Create XOR expression (nestable)
    pub fn xor(a: impl Into<Box<Expression>>, b: impl Into<Box<Expression>>) -> Self {
        Expression::Xor(a.into(), b.into())
    }
    
    /// Create AND expression (nestable)
    pub fn and(a: impl Into<Box<Expression>>, b: impl Into<Box<Expression>>) -> Self {
        Expression::And(a.into(), b.into())
    }
    
    /// Create NOT expression
    pub fn not(a: impl Into<Box<Expression>>) -> Self {
        Expression::Not(a.into())
    }
    
    /// Create shift expression
    pub fn shift(input: impl Into<Box<Expression>>, variant: ShiftVariant, amount: u8) -> Self {
        assert!(amount < 64, "Shift amount must be less than 64");
        Expression::Shift {
            input: input.into(),
            variant,
            amount,
        }
    }
    
    /// Create multiplication expression
    pub fn mul(a: impl Into<Box<Expression>>, b: impl Into<Box<Expression>>) -> Self {
        Expression::Mul(a.into(), b.into())
    }
    
    /// Check if this is a free operation (no constraint generation)
    pub fn is_free(&self) -> bool {
        match self {
            Expression::Var(_) => true,
            Expression::Xor(_, _) => true,
            Expression::Not(_) => true,
            Expression::Shift { .. } => true,
            Expression::And(_, _) => false,
            Expression::Mul(_, _) => false,
        }
    }
    
    /// Collect all witness variables referenced in this expression
    pub fn collect_vars(&self) -> Vec<WitnessVar> {
        let mut vars = Vec::new();
        self.collect_vars_impl(&mut vars);
        vars
    }
    
    fn collect_vars_impl(&self, vars: &mut Vec<WitnessVar>) {
        match self {
            Expression::Var(v) => vars.push(*v),
            Expression::Xor(a, b) | Expression::And(a, b) | Expression::Mul(a, b) => {
                a.collect_vars_impl(vars);
                b.collect_vars_impl(vars);
            }
            Expression::Not(a) | Expression::Shift { input: a, .. } => {
                a.collect_vars_impl(vars);
            }
        }
    }
    
    /// Simplify the expression (basic optimizations)
    pub fn simplify(self) -> Self {
        match self {
            // Double NOT cancels
            Expression::Not(boxed) => {
                if let Expression::Not(inner) = *boxed {
                    inner.simplify()
                } else {
                    Expression::Not(Box::new(boxed.simplify()))
                }
            }
            
            // XOR with self is zero
            Expression::Xor(a, b) => {
                let a_simplified = a.simplify();
                let b_simplified = b.simplify();
                
                if a_simplified == b_simplified {
                    // Should be constant 0, but we don't have constant in Expression
                    // For now just return the XOR
                    Expression::Xor(Box::new(a_simplified), Box::new(b_simplified))
                } else {
                    Expression::Xor(Box::new(a_simplified), Box::new(b_simplified))
                }
            }
            
            // Recurse for other operations
            Expression::And(a, b) => Expression::And(
                Box::new(a.simplify()),
                Box::new(b.simplify()),
            ),
            
            Expression::Shift { input, variant, amount } => Expression::Shift {
                input: Box::new(input.simplify()),
                variant,
                amount,
            },
            
            Expression::Mul(a, b) => Expression::Mul(
                Box::new(a.simplify()),
                Box::new(b.simplify()),
            ),
            
            // Variables are already simple
            Expression::Var(v) => Expression::Var(v),
        }
    }
}

impl From<WitnessVar> for Expression {
    fn from(var: WitnessVar) -> Self {
        Expression::Var(var)
    }
}

impl From<WitnessVar> for Box<Expression> {
    fn from(var: WitnessVar) -> Self {
        Box::new(Expression::Var(var))
    }
}