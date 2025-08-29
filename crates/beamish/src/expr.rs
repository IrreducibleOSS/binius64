//! Core expression type with phantom types for type safety

use std::marker::PhantomData;
use std::fmt;
use std::rc::Rc;

/// Internal representation of expression nodes
#[derive(Clone, Debug, PartialEq)]
pub enum ExprNode {
    /// Witness value (input)
    Witness(u32),
    /// Constant value
    Constant(u64),
    
    // Bitwise operations
    Xor(Rc<ExprNode>, Rc<ExprNode>),
    And(Rc<ExprNode>, Rc<ExprNode>),
    Or(Rc<ExprNode>, Rc<ExprNode>),
    Not(Rc<ExprNode>),
    
    // Shifts and rotations (with amount)
    Shl(Rc<ExprNode>, u8),
    Shr(Rc<ExprNode>, u8),
    Sar(Rc<ExprNode>, u8),
    Rol(Rc<ExprNode>, u8),
    Ror(Rc<ExprNode>, u8),
    
    // Arithmetic operations
    Add32(Rc<ExprNode>, Rc<ExprNode>),
    Add64(Rc<ExprNode>, Rc<ExprNode>),
    Sub32(Rc<ExprNode>, Rc<ExprNode>),
    Sub64(Rc<ExprNode>, Rc<ExprNode>),
    Mul32(Rc<ExprNode>, Rc<ExprNode>),
    Mul64(Rc<ExprNode>, Rc<ExprNode>),
    
    // Conditional/multiplexer
    Mux(Rc<ExprNode>, Rc<ExprNode>, Rc<ExprNode>), // cond ? true_val : false_val
    
    // Equality constraint
    Equal(Rc<ExprNode>, Rc<ExprNode>), // a = b
}

/// Type-safe expression with phantom type parameter
pub struct Expr<T> {
    pub(crate) inner: Rc<ExprNode>,
    _phantom: PhantomData<T>,
}

impl<T> Expr<T> {
    /// Create a new expression with the given node
    pub(crate) fn new(node: ExprNode) -> Self {
        Expr {
            inner: Rc::new(node),
            _phantom: PhantomData,
        }
    }
    
    /// Wrap an existing Rc<ExprNode>
    pub fn wrap(inner: Rc<ExprNode>) -> Self {
        Expr {
            inner,
            _phantom: PhantomData,
        }
    }
    
    /// Build a binary operation (helper to reduce boilerplate)
    pub(crate) fn binary(a: Expr<T>, b: Expr<T>, f: impl FnOnce(Rc<ExprNode>, Rc<ExprNode>) -> ExprNode) -> Self {
        Expr::new(f(a.inner, b.inner))
    }
    
    /// Build a unary operation (helper to reduce boilerplate)
    pub(crate) fn unary(a: Expr<T>, f: impl FnOnce(Rc<ExprNode>) -> ExprNode) -> Self {
        Expr::new(f(a.inner))
    }
}

impl<T> Clone for Expr<T> {
    fn clone(&self) -> Self {
        Expr {
            inner: self.inner.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T> fmt::Debug for Expr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Expr({:?})", self.inner)
    }
}

impl<T> fmt::Display for Expr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_node(&self.inner, f)
    }
}

fn fmt_node(node: &ExprNode, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match node {
        ExprNode::Witness(idx) => write!(f, "w{}", idx),
        ExprNode::Constant(val) => write!(f, "0x{:016x}", val),
        
        ExprNode::Xor(a, b) => write!(f, "({} ⊕ {})", fmt_str(a), fmt_str(b)),
        ExprNode::And(a, b) => write!(f, "({} ∧ {})", fmt_str(a), fmt_str(b)),
        ExprNode::Or(a, b) => write!(f, "({} ∨ {})", fmt_str(a), fmt_str(b)),
        ExprNode::Not(a) => write!(f, "¬{}", fmt_str(a)),
        
        ExprNode::Shl(a, n) => write!(f, "({} << {})", fmt_str(a), n),
        ExprNode::Shr(a, n) => write!(f, "({} >> {})", fmt_str(a), n),
        ExprNode::Sar(a, n) => write!(f, "({} >>> {})", fmt_str(a), n),
        ExprNode::Rol(a, n) => write!(f, "rol({}, {})", fmt_str(a), n),
        ExprNode::Ror(a, n) => write!(f, "ror({}, {})", fmt_str(a), n),
        
        ExprNode::Add32(a, b) => write!(f, "({} +₃₂ {})", fmt_str(a), fmt_str(b)),
        ExprNode::Add64(a, b) => write!(f, "({} +₆₄ {})", fmt_str(a), fmt_str(b)),
        ExprNode::Sub32(a, b) => write!(f, "({} -₃₂ {})", fmt_str(a), fmt_str(b)),
        ExprNode::Sub64(a, b) => write!(f, "({} -₆₄ {})", fmt_str(a), fmt_str(b)),
        ExprNode::Mul32(a, b) => write!(f, "({} ×₃₂ {})", fmt_str(a), fmt_str(b)),
        ExprNode::Mul64(a, b) => write!(f, "({} ×₆₄ {})", fmt_str(a), fmt_str(b)),
        
        ExprNode::Mux(c, t, fl) => write!(f, "({} ? {} : {})", fmt_str(c), fmt_str(t), fmt_str(fl)),
        ExprNode::Equal(a, b) => write!(f, "({} = {})", fmt_str(a), fmt_str(b)),
    }
}

fn fmt_str(node: &ExprNode) -> String {
    format!("{}", node)
}

impl fmt::Display for ExprNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_node(self, f)
    }
}

// Builder functions

/// Create a witness value (input to the circuit)
pub fn witness<T>(index: u32) -> Expr<T> {
    Expr::new(ExprNode::Witness(index))
}

/// Shorthand for witness value
pub fn val<T>(index: u32) -> Expr<T> {
    witness(index)
}

/// Create a constant value
pub fn constant<T>(value: u64) -> Expr<T> {
    Expr::new(ExprNode::Constant(value))
}

/// All-ones mask (0xFFFFFFFFFFFFFFFF)
pub fn ones<T>() -> Expr<T> {
    constant(0xFFFFFFFFFFFFFFFF)
}

/// Zero value
pub fn zero<T>() -> Expr<T> {
    constant(0)
}