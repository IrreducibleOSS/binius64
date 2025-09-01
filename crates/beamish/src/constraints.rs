//! Convert expressions to Binius64 constraints


use crate::expr::Expr;
use crate::optimize::OptConfig;
use std::fmt;
use log::debug;

/// A shifted value index: (value_id, shift_op, shift_amount)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShiftedValue {
    pub value_id: u32,
    pub shift_op: ShiftOp,
    pub shift_amount: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShiftOp {
    None,
    Shl,  // Logical left
    Shr,  // Logical right
    Sar,  // Arithmetic right
    Rol,  // Rotate left
    Ror,  // Rotate right
}

/// An operand is a XOR of shifted values (free in Binius64!)
#[derive(Debug, Clone)]
pub struct Operand {
    /// XOR of these shifted values
    pub terms: Vec<ShiftedValue>,
    /// Optional constant to XOR with
    pub constant: Option<u64>,
}

impl Operand {
    /// Create operand from a single value
    pub fn from_value(id: u32) -> Self {
        Self {
            terms: vec![ShiftedValue {
                value_id: id,
                shift_op: ShiftOp::None,
                shift_amount: 0,
            }],
            constant: None,
        }
    }
    
    /// Create operand from a constant
    pub fn from_constant(val: u64) -> Self {
        Self {
            terms: vec![],
            constant: Some(val),
        }
    }
    
    /// XOR two operands
    pub fn xor(mut self, other: Operand) -> Self {
        // Combine terms
        self.terms.extend(other.terms);
        
        // XOR constants
        match (self.constant, other.constant) {
            (Some(a), Some(b)) => self.constant = Some(a ^ b),
            (None, Some(b)) => self.constant = Some(b),
            (Some(a), None) => self.constant = Some(a),
            (None, None) => self.constant = None,
        }
        
        self
    }
}

impl fmt::Display for ShiftedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v[{}]", self.value_id)?;
        match self.shift_op {
            ShiftOp::None => Ok(()),
            ShiftOp::Shl => write!(f, "<<{}", self.shift_amount),
            ShiftOp::Shr => write!(f, ">>{}", self.shift_amount),
            ShiftOp::Sar => write!(f, ">>>{}", self.shift_amount),
            ShiftOp::Rol => write!(f, "<<<{}", self.shift_amount),
            ShiftOp::Ror => write!(f, ">>>{}", self.shift_amount),
        }
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terms.is_empty() && self.constant.is_none() {
            return write!(f, "0");
        }
        
        let mut first = true;
        for term in &self.terms {
            if !first {
                write!(f, " ⊕ ")?;
            }
            write!(f, "{}", term)?;
            first = false;
        }
        
        if let Some(c) = self.constant {
            if !first {
                write!(f, " ⊕ ")?;
            }
            if c == 0xFFFFFFFFFFFFFFFF {
                write!(f, "𝟙")?;
            } else {
                write!(f, "{:#x}", c)?;
            }
        }
        
        Ok(())
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constraint::And { a, b, c } => {
                write!(f, "({}) ∧ ({}) ⊕ ({}) = 0", a, b, c)
            }
            Constraint::Mul { a, b, hi, lo } => {
                write!(f, "({}) × ({}) = (v[{}] << 64) | v[{}]", a, b, hi, lo)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Constraint {
    /// AND constraint: A ∧ B ⊕ C = 0
    And {
        a: Operand,
        b: Operand,
        c: Operand,
    },
    /// MUL constraint: A × B = (HI << 64) | LO
    Mul {
        a: Operand,
        b: Operand,
        hi: u32,  // witness index for high 64 bits
        lo: u32,  // witness index for low 64 bits
    },
}

/// Convert an expression to constraints with optimization configuration
/// This generates constraints that compute the expression
/// PANICS if the expression cannot be compiled to constraints (e.g., pure XOR/NOT/rotation)
pub fn to_constraints<T>(expr: &Expr<T>, config: &OptConfig) -> Vec<Constraint> {
    debug!("");
    debug!(" CONSTRAINT TRANSLATION (Delayed Binding) ");
    debug!("INPUT:  {}", expr);
    
    let constraints = crate::optimize::optimize_and_generate(&expr.inner, config);
    
    // If no constraints were generated, the expression is purely operandic
    if constraints.is_empty() {
        panic!(
            "Cannot generate constraints for operandic expression: {}. \
            Bind via eq() or use within a constraining operation.",
            expr
        );
    }
    
    debug!("OUTPUT: {} constraints", constraints.len());
    
    constraints
}


/// Convert an expression to constraints with default configuration (all optimizations)
pub fn to_constraints_default<T>(expr: &Expr<T>) -> Vec<Constraint> {
    to_constraints(expr, &OptConfig::default())
}