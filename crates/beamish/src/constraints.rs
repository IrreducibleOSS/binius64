//! Convert expressions to Binius64 constraints

use crate::expr::{Expr, ExprNode};
use std::fmt;
use std::env;
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
    /// Optional constant XORed in
    pub constant: Option<u64>,
}

impl Operand {
    fn new() -> Self {
        Operand {
            terms: Vec::new(),
            constant: None,
        }
    }
    
    fn from_value(value_id: u32) -> Self {
        Operand {
            terms: vec![ShiftedValue {
                value_id,
                shift_op: ShiftOp::None,
                shift_amount: 0,
            }],
            constant: None,
        }
    }
    
    fn from_constant(val: u64) -> Self {
        Operand {
            terms: Vec::new(),
            constant: Some(val),
        }
    }
    
    fn xor(mut self, other: Operand) -> Self {
        self.terms.extend(other.terms);
        self.constant = match (self.constant, other.constant) {
            (None, None) => None,
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (Some(a), Some(b)) => Some(a ^ b),
        };
        self
    }
}

impl fmt::Display for ShiftedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.shift_op {
            ShiftOp::None => write!(f, "w{}", self.value_id),
            ShiftOp::Shl => write!(f, "(w{} << {})", self.value_id, self.shift_amount),
            ShiftOp::Shr => write!(f, "(w{} >> {})", self.value_id, self.shift_amount),
            ShiftOp::Sar => write!(f, "(w{} >>> {})", self.value_id, self.shift_amount),
            ShiftOp::Rol => write!(f, "(w{} <<< {})", self.value_id, self.shift_amount),
            ShiftOp::Ror => write!(f, "(w{} >>> {})", self.value_id, self.shift_amount),
        }
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        
        // Add shifted values
        for term in &self.terms {
            parts.push(term.to_string());
        }
        
        // Add constant if present
        if let Some(c) = self.constant {
            if c == 0xFFFFFFFFFFFFFFFF {
                parts.push("1*".to_string());
            } else if c == 0xFFFFFFFF {
                parts.push("MASK_32".to_string());
            } else {
                parts.push(format!("0x{:X}", c));
            }
        }
        
        if parts.is_empty() {
            write!(f, "0")
        } else if parts.len() == 1 {
            write!(f, "{}", parts[0])
        } else {
            write!(f, "({})", parts.join(" ⊕ "))
        }
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Constraint::And { a, b, c } => {
                write!(f, "{} ∧ {} ⊕ {} = 0", a, b, c)
            }
            Constraint::Mul { a, b, hi, lo } => {
                write!(f, "{} × {} = (w{} << 64) | w{}", a, b, hi, lo)
            }
        }
    }
}

/// Binius64 constraint types
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

/// Convert an expression to constraints with custom optimization configuration
/// This generates constraints that compute the expression
/// PANICS if the expression cannot be compiled to constraints (e.g., pure XOR/NOT/rotation)
pub fn to_constraints<T>(expr: &Expr<T>, config: &crate::optimize::OptimizationConfig) -> Vec<Constraint> {
    let mut constraints = Vec::new();
    let mut next_temp = 1000; // Temporary value IDs start at 1000
    
    // First optimize the expression with configuration
    let optimized = crate::optimize::optimize(expr, config);
    
    debug!("");
    debug!(" CONSTRAINT TRANSLATION ");
    debug!("INPUT:  {}", optimized);
    
    // Generate constraints - the result is left in an operand
    let _result_operand = emit_constraints_with_logging(&optimized.inner, config, &mut constraints, &mut next_temp, "");
    
    // If no constraints were generated, the expression is just operand manipulation
    // (XOR, NOT, shifts). These need an explicit equality constraint to be meaningful.
    if constraints.is_empty() {
        panic!(
            "Cannot generate constraints for expression: {}. \
            Expression contains only free operations (XOR, NOT, shifts). \
            Use eq() to create an equality constraint.",
            expr
        );
    }
    
    debug!("OUTPUT: {} constraints, {} auxiliary wires", 
        constraints.len(), 
        if next_temp > 1000 { next_temp - 1000 } else { 0 }
    );
    
    constraints
}

/// Convert an expression to constraints with default optimization configuration
pub fn to_constraints_default<T>(expr: &Expr<T>) -> Vec<Constraint> {
    to_constraints(expr, &crate::optimize::OptimizationConfig::default())
}

/// Check if verbose mode is enabled
fn is_verbose() -> bool {
    env::var("BEAMISH_VERBOSE").is_ok()
}

/// Emit constraints with debug logging
fn emit_constraints_with_logging(
    node: &ExprNode,
    config: &crate::optimize::OptimizationConfig,
    constraints: &mut Vec<Constraint>,
    next_temp: &mut u32,
    _context: &str,
) -> Operand {
    let initial_constraint_count = constraints.len();
    
    let result = emit_constraints(node, config, constraints, next_temp);
    
    // Log any new constraints that were emitted
    if constraints.len() > initial_constraint_count {
        for i in initial_constraint_count..constraints.len() {
            let c = &constraints[i];
            match c {
                Constraint::And { .. } => {
                    debug!("EMIT:   Constraint #{} (AND gate): {}", i + 1, c);
                }
                Constraint::Mul { .. } => {
                    debug!("EMIT:   Constraint #{} (MUL gate): {}", i + 1, c);
                }
            }
        }
    }
    
    result
}

/// Emit constraints for an expression node, returning the operand it evaluates to
fn emit_constraints(
    node: &ExprNode,
    config: &crate::optimize::OptimizationConfig,
    constraints: &mut Vec<Constraint>,
    next_temp: &mut u32,
) -> Operand {
    match node {
        ExprNode::Witness(idx) => Operand::from_value(*idx),
        ExprNode::Constant(val) => Operand::from_constant(*val),
        
        // XOR is free - just combine operands
        ExprNode::Xor(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            a_op.xor(b_op)
        }
        
        // AND needs a constraint
        ExprNode::And(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            let result_id = *next_temp;
            *next_temp += 1;
            
            constraints.push(Constraint::And {
                a: a_op,
                b: b_op,
                c: Operand::from_value(result_id),
            });
            
            Operand::from_value(result_id)
        }
        
        // OR = ¬(¬a ∧ ¬b) - needs constraints
        ExprNode::Or(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            
            // Create NOT of a and b (XOR with all-ones)
            let not_a = a_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF));
            let not_b = b_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF));
            
            // AND them
            let temp_and = *next_temp;
            *next_temp += 1;
            constraints.push(Constraint::And {
                a: not_a,
                b: not_b,
                c: Operand::from_value(temp_and),
            });
            
            // NOT the result
            Operand::from_value(temp_and).xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF))
        }
        
        // NOT is free - XOR with all-ones
        ExprNode::Not(a) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            a_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF))
        }
        
        // Shifts are free in operands
        ExprNode::Shl(a, amount) => emit_shifted(a, ShiftOp::Shl, *amount, config, constraints, next_temp),
        ExprNode::Shr(a, amount) => emit_shifted(a, ShiftOp::Shr, *amount, config, constraints, next_temp),
        ExprNode::Sar(a, amount) => emit_shifted(a, ShiftOp::Sar, *amount, config, constraints, next_temp),
        ExprNode::Rol(a, amount) => emit_shifted(a, ShiftOp::Rol, *amount, config, constraints, next_temp),
        ExprNode::Ror(a, amount) => emit_shifted(a, ShiftOp::Ror, *amount, config, constraints, next_temp),
        
        // Arithmetic operations use carry propagation with AND constraints
        ExprNode::Add32(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            
            // Auxiliary wire for carry bits
            let cout = *next_temp;
            *next_temp += 1;
            
            // Result wire
            let result = *next_temp;
            *next_temp += 1;
            
            // Carry propagation constraint:
            // (a ⊕ (cout << 1)) ∧ (b ⊕ (cout << 1)) = cout ⊕ (cout << 1)
            let cout_shifted = Operand {
                terms: vec![ShiftedValue {
                    value_id: cout,
                    shift_op: ShiftOp::Shl,
                    shift_amount: 1,
                }],
                constant: None,
            };
            
            constraints.push(Constraint::And {
                a: a_op.clone().xor(cout_shifted.clone()),
                b: b_op.clone().xor(cout_shifted.clone()),
                c: Operand::from_value(cout).xor(cout_shifted.clone()),
            });
            
            // Result masking constraint for 32-bit:
            // (a ⊕ b ⊕ (cout << 1)) ∧ MASK_32 = result
            constraints.push(Constraint::And {
                a: a_op.xor(b_op).xor(cout_shifted),
                b: Operand::from_constant(0xFFFFFFFF), // MASK_32
                c: Operand::from_value(result),
            });
            
            Operand::from_value(result)
        }
        
        ExprNode::Add64(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            
            // Auxiliary wire for carry bits
            let cout = *next_temp;
            *next_temp += 1;
            
            // Result wire
            let result = *next_temp;
            *next_temp += 1;
            
            // Carry propagation constraint:
            // (a ⊕ (cout << 1)) ∧ (b ⊕ (cout << 1)) = cout ⊕ (cout << 1)
            let cout_shifted = Operand {
                terms: vec![ShiftedValue {
                    value_id: cout,
                    shift_op: ShiftOp::Shl,
                    shift_amount: 1,
                }],
                constant: None,
            };
            
            constraints.push(Constraint::And {
                a: a_op.clone().xor(cout_shifted.clone()),
                b: b_op.clone().xor(cout_shifted.clone()),
                c: Operand::from_value(cout).xor(cout_shifted.clone()),
            });
            
            // Sum computation constraint:
            // (a ⊕ b ⊕ (cout << 1)) ∧ 𝟙 = sum
            constraints.push(Constraint::And {
                a: a_op.xor(b_op).xor(cout_shifted),
                b: Operand::from_constant(0xFFFFFFFFFFFFFFFF), // All ones
                c: Operand::from_value(result),
            });
            
            Operand::from_value(result)
        }
        
        ExprNode::Sub32(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            
            // Auxiliary wire for borrow bits
            let bout = *next_temp;
            *next_temp += 1;
            
            // Result wire
            let result = *next_temp;
            *next_temp += 1;
            
            // Borrow propagation constraint:
            // ((a ⊕ 𝟙) ⊕ (bout << 1)) ∧ (b ⊕ (bout << 1)) = bout ⊕ (bout << 1)
            let bout_shifted = Operand {
                terms: vec![ShiftedValue {
                    value_id: bout,
                    shift_op: ShiftOp::Shl,
                    shift_amount: 1,
                }],
                constant: None,
            };
            
            let not_a = a_op.clone().xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF));
            
            constraints.push(Constraint::And {
                a: not_a.xor(bout_shifted.clone()),
                b: b_op.clone().xor(bout_shifted.clone()),
                c: Operand::from_value(bout).xor(bout_shifted.clone()),
            });
            
            // Result masking constraint for 32-bit:
            // (a ⊕ b ⊕ (bout << 1)) ∧ MASK_32 = result
            constraints.push(Constraint::And {
                a: a_op.xor(b_op).xor(bout_shifted),
                b: Operand::from_constant(0xFFFFFFFF), // MASK_32
                c: Operand::from_value(result),
            });
            
            Operand::from_value(result)
        }
        
        ExprNode::Sub64(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            
            // Auxiliary wire for borrow bits
            let bout = *next_temp;
            *next_temp += 1;
            
            // Result wire
            let result = *next_temp;
            *next_temp += 1;
            
            // Borrow propagation constraint:
            // ((a ⊕ 𝟙) ⊕ (bout << 1)) ∧ (b ⊕ (bout << 1)) = bout ⊕ (bout << 1)
            let bout_shifted = Operand {
                terms: vec![ShiftedValue {
                    value_id: bout,
                    shift_op: ShiftOp::Shl,
                    shift_amount: 1,
                }],
                constant: None,
            };
            
            let not_a = a_op.clone().xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF));
            
            constraints.push(Constraint::And {
                a: not_a.xor(bout_shifted.clone()),
                b: b_op.clone().xor(bout_shifted.clone()),
                c: Operand::from_value(bout).xor(bout_shifted.clone()),
            });
            
            // Difference computation constraint:
            // (a ⊕ b ⊕ (bout << 1)) ∧ 𝟙 = diff
            constraints.push(Constraint::And {
                a: a_op.xor(b_op).xor(bout_shifted),
                b: Operand::from_constant(0xFFFFFFFFFFFFFFFF), // All ones
                c: Operand::from_value(result),
            });
            
            Operand::from_value(result)
        }
        
        ExprNode::Mul32(a, b) | ExprNode::Mul64(a, b) => {
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            let lo = *next_temp;
            let hi = *next_temp + 1;
            *next_temp += 2;
            
            constraints.push(Constraint::Mul {
                a: a_op,
                b: b_op,
                hi,
                lo,
            });
            
            Operand::from_value(lo)
        }
        
        // Equality constraint: a = b
        ExprNode::Equal(a, b) => {
            // Check for Masked AND-XOR pattern if optimization is enabled
            if config.masked_and_xor_fusion {
                // Check for pattern: witness = a ⊕ ((¬b) ∧ c)
                if let ExprNode::Witness(result_id) = &**a {
                if let ExprNode::Xor(xor_a, and_part) = &**b {
                    if let ExprNode::And(not_part, c) = &**and_part {
                        if let ExprNode::Not(not_b) = &**not_part {
                            // Found pattern: result = a ⊕ ((¬b) ∧ c)
                            // Optimize to single constraint: (b ⊕ 1) ∧ c ⊕ (a ⊕ result) = 0
                            debug!("OPTIMIZE: Masked AND-XOR pattern → single constraint");
                            let a_op = emit_constraints(xor_a, config, constraints, next_temp);
                            let b_op = emit_constraints(not_b, config, constraints, next_temp);
                            let c_op = emit_constraints(c, config, constraints, next_temp);
                            
                            constraints.push(Constraint::And {
                                a: b_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF)), // (b ⊕ 1)
                                b: c_op,
                                c: a_op.xor(Operand::from_value(*result_id)), // (a ⊕ result)
                            });
                            
                            return Operand::from_value(*result_id);
                        }
                    }
                }
                }
                
                // Also check reverse: a ⊕ ((¬b) ∧ c) = witness
                if let ExprNode::Witness(result_id) = &**b {
                if let ExprNode::Xor(xor_a, and_part) = &**a {
                    if let ExprNode::And(not_part, c) = &**and_part {
                        if let ExprNode::Not(not_b) = &**not_part {
                            // Found pattern: a ⊕ ((¬b) ∧ c) = result
                            debug!("OPTIMIZE: Masked AND-XOR pattern → single constraint");
                            let a_op = emit_constraints(xor_a, config, constraints, next_temp);
                            let b_op = emit_constraints(not_b, config, constraints, next_temp);
                            let c_op = emit_constraints(c, config, constraints, next_temp);
                            
                            constraints.push(Constraint::And {
                                a: b_op.xor(Operand::from_constant(0xFFFFFFFFFFFFFFFF)), // (b ⊕ 1)
                                b: c_op,
                                c: a_op.xor(Operand::from_value(*result_id)), // (a ⊕ result)
                            });
                            
                            return Operand::from_value(*result_id);
                        }
                    }
                }
                }
            } // End of masked_and_xor_fusion check
            
            // Default equality constraint
            let a_op = emit_constraints(a, config, constraints, next_temp);
            let b_op = emit_constraints(b, config, constraints, next_temp);
            
            // Generate constraint: (a ⊕ b) ∧ 𝟙 ⊕ 0 = 0
            // This simplifies to: a ⊕ b = 0
            constraints.push(Constraint::And {
                a: a_op.xor(b_op),
                b: Operand::from_constant(0xFFFFFFFFFFFFFFFF),
                c: Operand::from_constant(0),
            });
            
            // Return zero operand (the constraint evaluates to 0)
            Operand::from_constant(0)
        }
        
        // Multiplexer: cond ? true_val : false_val
        ExprNode::Mux(cond, true_val, false_val) => {
            let cond_op = emit_constraints(cond, config, constraints, next_temp);
            let true_op = emit_constraints(true_val, config, constraints, next_temp);
            let false_op = emit_constraints(false_val, config, constraints, next_temp);
            
            // From C.11: result = cond ∧ (true ⊕ false) ⊕ false
            // This reduces to single AND constraint: 
            // cond ∧ (true ⊕ false) ⊕ (result ⊕ false) = 0
            let result = *next_temp;
            *next_temp += 1;
            
            // Create the (true ⊕ false) operand
            let true_xor_false = true_op.xor(false_op.clone());
            
            // Create (result ⊕ false) for the output
            let result_xor_false = Operand::from_value(result).xor(false_op);
            
            constraints.push(Constraint::And {
                a: cond_op,
                b: true_xor_false,
                c: result_xor_false,
            });
            
            Operand::from_value(result)
        }
    }
}

/// Handle shifted expressions
fn emit_shifted(
    expr: &ExprNode,
    shift_op: ShiftOp,
    amount: u8,
    config: &crate::optimize::OptimizationConfig,
    constraints: &mut Vec<Constraint>,
    next_temp: &mut u32,
) -> Operand {
    // If the inner expression is just a witness, we can directly create a shifted operand
    if let ExprNode::Witness(idx) = expr {
        return Operand {
            terms: vec![ShiftedValue {
                value_id: *idx,
                shift_op,
                shift_amount: amount,
            }],
            constant: None,
        };
    }
    
    // Otherwise, evaluate the expression first then apply shift
    // (This is simplified - a full implementation would optimize more cases)
    let inner = emit_constraints(expr, config, constraints, next_temp);
    
    // For now, create a temporary and apply shift
    let temp = *next_temp;
    *next_temp += 1;
    
    // Store inner result in temp
    constraints.push(Constraint::And {
        a: inner,
        b: Operand::from_constant(0xFFFFFFFFFFFFFFFF), // AND with all-ones
        c: Operand::from_value(temp),
    });
    
    // Return shifted temp
    Operand {
        terms: vec![ShiftedValue {
            value_id: temp,
            shift_op,
            shift_amount: amount,
        }],
        constant: None,
    }
}