//! Expression trees - recipes for constraint generation
//!
//! Uses the Beamish pattern: only Call nodes that compute values,
//! all operation logic lives in the ops layer.

use crate::types::BitType;
use std::rc::Rc;

/// Expression node - only knows how to call functions for computation
#[derive(Debug)]
pub enum ExprNode {
    /// Constant value
    Constant(u64),
    
    /// Witness value (provided during solving)
    Witness(u32),
    
    /// Call a function to compute result - this is the only computation type
    Call {
        compute: fn(&[u64]) -> u64,
        inputs: Vec<Rc<ExprNode>>,
    },
}

/// Typed expression wrapper
#[derive(Debug, Clone)]
pub struct Expr<T: BitType> {
    pub inner: Rc<ExprNode>,
    phantom: std::marker::PhantomData<T>,
}

impl<T: BitType> Expr<T> {
    pub fn new(node: ExprNode) -> Self {
        Self {
            inner: Rc::new(node),
            phantom: std::marker::PhantomData,
        }
    }
    
    pub fn wrap(inner: Rc<ExprNode>) -> Self {
        Self {
            inner,
            phantom: std::marker::PhantomData,
        }
    }
}

// Constructor functions

/// Create a constant expression
pub fn constant<T: BitType>(value: u64) -> Expr<T> {
    Expr::new(ExprNode::Constant(value))
}

/// Create a witness expression
pub fn witness<T: BitType>(index: u32) -> Expr<T> {
    Expr::new(ExprNode::Witness(index))
}

/// Create a witness expression (short name)
pub fn val<T: BitType>(index: u32) -> Expr<T> {
    Expr::new(ExprNode::Witness(index))
}

/// Zero constant
pub fn zero<T: BitType>() -> Expr<T> {
    constant(T::zero())
}

/// All-ones constant
pub fn ones<T: BitType>() -> Expr<T> {
    constant(T::ones())
}