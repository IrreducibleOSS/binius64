//! Core type definitions for the Beamish compiler

use std::collections::{HashMap, HashSet};

/// Unique identifier for a witness variable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WitnessId {
    Public(PublicId),
    Auxiliary(AuxiliaryId),
}

/// Public witness identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicId(pub u32);

/// Auxiliary witness identifier  
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuxiliaryId(pub u32);

/// Variable identifier in semantic expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(pub u32);

/// Auxiliary witness tracking
#[derive(Debug, Clone)]
pub struct AuxiliaryGraph {
    pub nodes: HashMap<AuxiliaryId, AuxiliaryNode>,
    pub edges: Vec<(AuxiliaryId, AuxiliaryId)>, // src → dst dependencies
}

#[derive(Debug, Clone)]
pub struct AuxiliaryNode {
    pub id: AuxiliaryId,
    pub source: AuxiliarySource,
    pub dependents: Vec<AuxiliaryId>,
    pub elimination_status: EliminationStatus,
}

#[derive(Debug, Clone)]
pub enum AuxiliarySource {
    /// Deterministically computed from other witnesses
    Computed(Box<SemExpr>),
    /// Non-deterministically chosen (e.g., division quotient)
    Existential(ExistentialComputation),
}

#[derive(Debug, Clone)]
pub enum ExistentialComputation {
    /// Quotient from division: q = ⌊a/n⌋
    DivQuotient { dividend: WitnessId, divisor: WitnessId },
    /// Other existential computations
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EliminationStatus {
    /// Appears in final constraints
    Required,
    /// Packed away but computation preserved
    Eliminated,
    /// Needed for computing other auxiliaries
    Intermediate,
}

/// Semantic expression (Level 1 IR)
#[derive(Debug, Clone)]
pub enum SemExpr {
    Var(VarId),
    Const(u64),
    
    // Arithmetic semantics
    Add(Box<SemExpr>, Box<SemExpr>),
    Mul(Box<SemExpr>, Box<SemExpr>),
    Div(Box<SemExpr>, Box<SemExpr>), // Creates auxiliary quotient
    Mod(Box<SemExpr>, Box<SemExpr>), // Creates auxiliary quotient
    
    // Bitwise semantics
    Xor(Box<SemExpr>, Box<SemExpr>),
    And(Box<SemExpr>, Box<SemExpr>),
    Not(Box<SemExpr>),
    
    // Shifts and rotations
    Shl(Box<SemExpr>, u8),
    Shr(Box<SemExpr>, u8),
    Rotl(Box<SemExpr>, u8),
    Rotr(Box<SemExpr>, u8),
    
    // Existential auxiliary witness
    Auxiliary { 
        id: AuxiliaryId, 
        verifier: Box<SemExpr> 
    },
}

/// Shift operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftOp {
    Sll, // Logical left
    Slr, // Logical right  
    Sar, // Arithmetic right
}

/// A term in an operand (witness with optional shift)
#[derive(Debug, Clone)]
pub struct Term {
    pub witness: WitnessId,
    pub shift: Option<(ShiftOp, u8)>,
}

/// An operand (sum of shifted witnesses plus optional constant)
#[derive(Debug, Clone)]
pub struct Operand {
    pub terms: Vec<Term>,
    pub constant: Option<u64>,
}

/// Binius constraint types
#[derive(Debug, Clone)]
pub enum BiniusConstraint {
    /// AND constraint: (A) & (B) ⊕ (C) = 0
    And {
        a: Operand,
        b: Operand,
        c: Operand,
    },
    /// MUL constraint: (A) × (B) = (HI << 64) | LO
    Mul {
        a: Operand,
        b: Operand,
        hi: WitnessId,
        lo: WitnessId,
    },
}