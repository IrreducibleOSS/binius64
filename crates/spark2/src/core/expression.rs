//! Expression AST for representing operations before constraint generation

use std::fmt;

/// A value reference in the expression system
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Value {
    /// Index of the value in the witness vector
    pub index: u32,
    /// Optional name for debugging
    pub name: Option<String>,
}

impl Value {
    pub fn new(index: u32) -> Self {
        Self { index, name: None }
    }
    
    pub fn named(index: u32, name: impl Into<String>) -> Self {
        Self {
            index,
            name: Some(name.into()),
        }
    }
}

/// Binary operations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    /// Bitwise XOR (field addition in GF(2^64))
    Xor,
    /// Bitwise AND
    And,
    /// Bitwise OR  
    Or,
    /// Unsigned addition (with carry)
    Add,
    /// Unsigned multiplication
    Mul,
}

/// Unary operations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    /// Bitwise NOT
    Not,
    /// Logical shift left
    Shl(u8),
    /// Logical shift right
    Shr(u8),
    /// Arithmetic shift right
    Sar(u8),
    /// Rotate left
    Rol(u8),
    /// Rotate right
    Ror(u8),
}

/// Expression tree representing operations
#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    /// Leaf: a value reference
    Value(Value),
    /// Leaf: a constant
    Const(u64),
    /// Binary operation
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    /// Unary operation
    Unary {
        op: UnOp,
        expr: Box<Expr>,
    },
    /// Conditional (ternary) operation
    Cond {
        cond: Box<Expr>,
        if_true: Box<Expr>,
        if_false: Box<Expr>,
    },
}

impl Expr {
    /// Create a value reference
    pub fn val(index: u32) -> Self {
        Expr::Value(Value::new(index))
    }
    
    /// Create a named value reference
    pub fn named_val(index: u32, name: impl Into<String>) -> Self {
        Expr::Value(Value::named(index, name))
    }
    
    /// Create a constant
    pub fn constant(value: u64) -> Self {
        Expr::Const(value)
    }
    
    /// XOR two expressions
    pub fn xor(self, other: Expr) -> Self {
        Expr::Binary {
            op: BinOp::Xor,
            left: Box::new(self),
            right: Box::new(other),
        }
    }
    
    /// AND two expressions
    pub fn and(self, other: Expr) -> Self {
        Expr::Binary {
            op: BinOp::And,
            left: Box::new(self),
            right: Box::new(other),
        }
    }
    
    /// OR two expressions
    pub fn or(self, other: Expr) -> Self {
        Expr::Binary {
            op: BinOp::Or,
            left: Box::new(self),
            right: Box::new(other),
        }
    }
    
    /// NOT an expression
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Self {
        Expr::Unary {
            op: UnOp::Not,
            expr: Box::new(self),
        }
    }
    
    /// Shift left
    #[allow(clippy::should_implement_trait)]
    pub fn shl(self, amount: u8) -> Self {
        Expr::Unary {
            op: UnOp::Shl(amount),
            expr: Box::new(self),
        }
    }
    
    /// Shift right (logical)
    #[allow(clippy::should_implement_trait)]
    pub fn shr(self, amount: u8) -> Self {
        Expr::Unary {
            op: UnOp::Shr(amount),
            expr: Box::new(self),
        }
    }
    
    /// Shift right (arithmetic)
    pub fn sar(self, amount: u8) -> Self {
        Expr::Unary {
            op: UnOp::Sar(amount),
            expr: Box::new(self),
        }
    }
    
    /// Rotate right
    pub fn ror(self, amount: u8) -> Self {
        Expr::Unary {
            op: UnOp::Ror(amount),
            expr: Box::new(self),
        }
    }
    
    /// Conditional expression
    pub fn cond(cond: Expr, if_true: Expr, if_false: Expr) -> Self {
        Expr::Cond {
            cond: Box::new(cond),
            if_true: Box::new(if_true),
            if_false: Box::new(if_false),
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Expr::Value(v) => {
                if let Some(name) = &v.name {
                    write!(f, "{}", name)
                } else {
                    write!(f, "v[{}]", v.index)
                }
            }
            Expr::Const(c) => write!(f, "0x{:016x}", c),
            Expr::Binary { op, left, right } => {
                let op_str = match op {
                    BinOp::Xor => "^",
                    BinOp::And => "&",
                    BinOp::Or => "|",
                    BinOp::Add => "+",
                    BinOp::Mul => "*",
                };
                write!(f, "({} {} {})", left, op_str, right)
            }
            Expr::Unary { op, expr } => match op {
                UnOp::Not => write!(f, "~{}", expr),
                UnOp::Shl(n) => write!(f, "({} << {})", expr, n),
                UnOp::Shr(n) => write!(f, "({} >> {})", expr, n),
                UnOp::Sar(n) => write!(f, "({} >>> {})", expr, n),
                UnOp::Rol(n) => write!(f, "rol({}, {})", expr, n),
                UnOp::Ror(n) => write!(f, "ror({}, {})", expr, n),
            },
            Expr::Cond { cond, if_true, if_false } => {
                write!(f, "({} ? {} : {})", cond, if_true, if_false)
            }
        }
    }
}

/// Helper macro for building expressions
#[macro_export]
macro_rules! expr {
    // Value
    (v[$idx:expr]) => {
        $crate::Expr::val($idx)
    };
    // Named value
    ($name:ident : $idx:expr) => {
        $crate::Expr::named_val($idx, stringify!($name))
    };
    // Constant
    ($val:literal) => {
        $crate::Expr::constant($val)
    };
    // XOR
    ($left:tt ^ $right:tt) => {
        expr!($left).xor(expr!($right))
    };
    // AND
    ($left:tt & $right:tt) => {
        expr!($left).and(expr!($right))
    };
    // OR
    ($left:tt | $right:tt) => {
        expr!($left).or(expr!($right))
    };
    // NOT
    (!$expr:tt) => {
        expr!($expr).not()
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_expression_building() {
        // Test basic XOR chain
        let expr = Expr::val(0)
            .xor(Expr::val(1))
            .xor(Expr::val(2));
        
        assert_eq!(format!("{}", expr), "((v[0] ^ v[1]) ^ v[2])");
        
        // Test Keccak chi pattern
        let chi = Expr::val(0).xor(
            Expr::val(1).not().and(Expr::val(2))
        );
        
        assert_eq!(format!("{}", chi), "(v[0] ^ (~v[1] & v[2]))");
        
        // Test SHA sigma pattern
        let sigma = Expr::val(0).ror(2)
            .xor(Expr::val(0).ror(13))
            .xor(Expr::val(0).ror(22));
        
        assert_eq!(format!("{}", sigma), "((ror(v[0], 2) ^ ror(v[0], 13)) ^ ror(v[0], 22))");
    }
}