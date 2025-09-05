//! Typed value system that creates recipes using existing recipe system

use crate::{
    expression::{Expression, ShiftVariant},
    witness::WitnessVar,
};

/// A 32-bit unsigned integer value
#[derive(Debug, Clone)]
pub struct U32Value {
    var: WitnessVar,
}

impl U32Value {
    /// Create a new U32 value
    pub fn new(var: WitnessVar) -> Self {
        Self { var }
    }
    
    /// Get the witness variable
    pub fn var(&self) -> WitnessVar {
        self.var
    }
    
    /// Convert to expression  
    pub fn to_expression(&self) -> Expression {
        Expression::var(self.var)
    }
    
    /// Create XOR expression with another U32 value
    pub fn xor(&self, other: &U32Value) -> Expression {
        Expression::xor(self.var, other.var)
    }
    
    /// Create AND expression with another U32 value
    pub fn and(&self, other: &U32Value) -> Expression {
        Expression::and(self.var, other.var)
    }
    
    /// Create NOT expression
    pub fn not(&self) -> Expression {
        Expression::not(self.var)
    }
    
    /// Create left shift expression
    pub fn shl(&self, amount: u8) -> Expression {
        Expression::shift(self.var, ShiftVariant::Sll, amount)
    }
    
    /// Create right shift (logical) expression
    pub fn shr(&self, amount: u8) -> Expression {
        Expression::shift(self.var, ShiftVariant::Slr, amount)
    }
    
    /// Create right shift (arithmetic) expression
    pub fn sar(&self, amount: u8) -> Expression {
        Expression::shift(self.var, ShiftVariant::Sar, amount)
    }
    
    /// Create multiplication expression
    pub fn mul(&self, other: &U32Value) -> Expression {
        Expression::mul(self.var, other.var)
    }
    
    /// Create multiplication expression for high bits
    pub fn mul_high(&self, other: &U32Value) -> Expression {
        Expression::mul_high(self.var, other.var)
    }
}

/// A 64-bit unsigned integer value
#[derive(Debug, Clone)]
pub struct U64Value {
    var: WitnessVar,
}

impl U64Value {
    pub fn new(var: WitnessVar) -> Self {
        Self { var }
    }
    
    pub fn var(&self) -> WitnessVar {
        self.var
    }
    
    pub fn to_expression(&self) -> Expression {
        Expression::var(self.var)
    }
    
    pub fn xor(&self, other: &U64Value) -> Expression {
        Expression::xor(self.var, other.var)
    }
    
    pub fn and(&self, other: &U64Value) -> Expression {
        Expression::and(self.var, other.var)
    }
    
    pub fn not(&self) -> Expression {
        Expression::not(self.var)
    }
    
    pub fn shl(&self, amount: u8) -> Expression {
        Expression::shift(self.var, ShiftVariant::Sll, amount)
    }
    
    pub fn shr(&self, amount: u8) -> Expression {
        Expression::shift(self.var, ShiftVariant::Slr, amount)
    }
    
    pub fn sar(&self, amount: u8) -> Expression {
        Expression::shift(self.var, ShiftVariant::Sar, amount)
    }
    
    pub fn mul(&self, other: &U64Value) -> Expression {
        Expression::mul(self.var, other.var)
    }
    
    pub fn mul_high(&self, other: &U64Value) -> Expression {
        Expression::mul_high(self.var, other.var)
    }
}

/// A field element value
#[derive(Debug, Clone)]
pub struct Field64Value {
    var: WitnessVar,
}

impl Field64Value {
    pub fn new(var: WitnessVar) -> Self {
        Self { var }
    }
    
    pub fn var(&self) -> WitnessVar {
        self.var
    }
    
    pub fn to_expression(&self) -> Expression {
        Expression::var(self.var)
    }
    
    pub fn xor(&self, other: &Field64Value) -> Expression {
        Expression::xor(self.var, other.var)
    }
    
    pub fn mul(&self, other: &Field64Value) -> Expression {
        Expression::mul(self.var, other.var)
    }
    
    pub fn mul_high(&self, other: &Field64Value) -> Expression {
        Expression::mul_high(self.var, other.var)
    }
}