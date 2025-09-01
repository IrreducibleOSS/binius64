//! Core expression type with phantom types for type safety

use std::marker::PhantomData;
use std::fmt;
use std::rc::Rc;

/// Internal representation of expression nodes
#[derive(Clone, Debug)]
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
    
    // Black box computed value
    BlackBox {
        compute: fn(&[u64]) -> u64,
        inputs: Vec<Rc<ExprNode>>,
    }
}

impl PartialEq for ExprNode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ExprNode::Witness(a), ExprNode::Witness(b)) => a == b,
            (ExprNode::Constant(a), ExprNode::Constant(b)) => a == b,
            
            (ExprNode::Xor(a1, a2), ExprNode::Xor(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::And(a1, a2), ExprNode::And(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::Or(a1, a2), ExprNode::Or(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::Not(a), ExprNode::Not(b)) => a == b,
            
            (ExprNode::Shl(a1, n1), ExprNode::Shl(a2, n2)) => a1 == a2 && n1 == n2,
            (ExprNode::Shr(a1, n1), ExprNode::Shr(a2, n2)) => a1 == a2 && n1 == n2,
            (ExprNode::Sar(a1, n1), ExprNode::Sar(a2, n2)) => a1 == a2 && n1 == n2,
            (ExprNode::Rol(a1, n1), ExprNode::Rol(a2, n2)) => a1 == a2 && n1 == n2,
            (ExprNode::Ror(a1, n1), ExprNode::Ror(a2, n2)) => a1 == a2 && n1 == n2,
            
            (ExprNode::Add32(a1, a2), ExprNode::Add32(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::Add64(a1, a2), ExprNode::Add64(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::Sub32(a1, a2), ExprNode::Sub32(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::Sub64(a1, a2), ExprNode::Sub64(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::Mul32(a1, a2), ExprNode::Mul32(b1, b2)) => a1 == b1 && a2 == b2,
            (ExprNode::Mul64(a1, a2), ExprNode::Mul64(b1, b2)) => a1 == b1 && a2 == b2,
            
            (ExprNode::Mux(c1, t1, f1), ExprNode::Mux(c2, t2, f2)) => c1 == c2 && t1 == t2 && f1 == f2,
            (ExprNode::Equal(a1, a2), ExprNode::Equal(b1, b2)) => a1 == b1 && a2 == b2,
            
            (ExprNode::BlackBox { compute: c1, inputs: i1 }, ExprNode::BlackBox { compute: c2, inputs: i2 }) => {
                // Compare function pointers by address and inputs
                std::ptr::eq(c1 as *const _, c2 as *const _) && i1 == i2
            }
            
            _ => false,
        }
    }
}

impl ExprNode {
    /// Get witness ID if this is a witness node
    pub fn as_witness(&self) -> Option<u32> {
        match self {
            ExprNode::Witness(id) => Some(*id),
            _ => None,
        }
    }
}

/// Type-safe expression with phantom type parameter
pub struct Expr<T> {
    pub inner: Rc<ExprNode>,
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
}

impl<T> Clone for Expr<T> {
    fn clone(&self) -> Self {
        Expr {
            inner: self.inner.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T> Expr<T> {
    /// Cast expression to a different phantom type
    /// Safe because the underlying ExprNode is untyped
    pub fn cast<U>(&self) -> Expr<U> {
        Expr::wrap(self.inner.clone())
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
        
        ExprNode::BlackBox { inputs, .. } => {
            match inputs.len() {
                1 => write!(f, "blackbox({})", fmt_str(&inputs[0])),
                2 => write!(f, "blackbox({}, {})", fmt_str(&inputs[0]), fmt_str(&inputs[1])),
                _ => write!(f, "blackbox({} inputs)", inputs.len()),
            }
        }
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