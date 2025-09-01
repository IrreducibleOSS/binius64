//! Compute and evaluate expressions and constraints

pub mod constraints;
pub mod expressions;

pub use expressions::ExpressionEvaluator;
pub use constraints::ConstraintValidator;