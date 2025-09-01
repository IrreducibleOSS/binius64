//! Expression evaluation for witness generation
//!
//! Evaluates expressions with concrete witness values.

use crate::expr::Expr;
use crate::compute::constraints::ConstraintValidator;

/// Evaluates expressions with concrete witness values
pub struct ExpressionEvaluator {
    validator: ConstraintValidator,
}

impl ExpressionEvaluator {
    /// Create a new evaluator with given witness values
    pub fn new(witness_values: Vec<u64>) -> Self {
        Self {
            validator: ConstraintValidator::new(witness_values),
        }
    }
    
    /// Set a witness value at index
    pub fn set_witness(&mut self, index: usize, value: u64) {
        self.validator.set_witness(index, value);
    }
    
    /// Evaluate an expression and return the result
    pub fn evaluate<T>(&mut self, expr: &Expr<T>) -> u64 {
        self.validator.evaluate_expr(expr.inner.as_ref())
    }
}