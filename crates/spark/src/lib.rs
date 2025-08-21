//! Spark: A new paradigm for ZK proof construction
//!
//! This module implements a dual-language architecture that separates:
//! 1. Witness computation (imperative Rust code)
//! 2. Constraint generation (declarative compilation)
//!
//! The key insight: constraints are a compilation target, not a programming model.

pub mod witness;
pub mod constraints;
pub mod compiler;  // Direct compilation to backend constraints only!
pub mod examples;

#[cfg(test)]
mod tests;

use binius_core::Word;

// Typed witness IDs for different semantic interpretations
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FieldId(pub u32);  // Binary field element GF(2^64)

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UIntId(pub u32);   // Unsigned 64-bit integer

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BitsId(pub u32);   // Raw bit pattern

// Typed tracked values with semantic clarity
#[derive(Clone, Copy, Debug)]
pub struct FieldValue {
    /// The value interpreted as a field element in GF(2^64)
    pub value: Word,
    /// Field-typed identifier
    pub id: FieldId,
}

#[derive(Clone, Copy, Debug)]
pub struct UIntValue {
    /// The value interpreted as unsigned 64-bit integer
    pub value: Word,
    /// Integer-typed identifier
    pub id: UIntId,
}

#[derive(Clone, Copy, Debug)]
pub struct BitsValue {
    /// The value interpreted as raw bit pattern
    pub value: Word,
    /// Bits-typed identifier
    pub id: BitsId,
}

// Legacy types for gradual migration
#[derive(Clone, Copy, Debug)]
pub struct TrackedWord {
    /// The actual value during witness computation
    pub value: Word,
    /// Unique identifier for constraint tracking
    pub id: WitnessId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WitnessId(pub u32);

// Typed operation hierarchy with 1-1 method mapping

/// Field operations in GF(2^64)
#[derive(Clone, Debug)]
pub enum FieldOp {
    Add(FieldId, FieldId, FieldId),   // a + b = result (XOR)
    Mul(FieldId, FieldId, FieldId),   // a * b = result (CLMUL)
}

/// Unsigned integer operations mod 2^64  
#[derive(Clone, Debug)]
pub enum UIntOp {
    Add(UIntId, UIntId, UIntId, UIntId, UIntId), // a + b + cin = sum, cout
    Mul(UIntId, UIntId, UIntId, UIntId),         // a * b = lo, hi
}

/// Bit pattern operations
#[derive(Clone, Debug)]
pub enum BitsOp {
    And(BitsId, BitsId, BitsId),      // a & b = result
    Or(BitsId, BitsId, BitsId),       // a | b = result
    Not(BitsId, BitsId),              // !a = result
    Shl(BitsId, u32, BitsId),         // a << n = result
    Shr(BitsId, u32, BitsId),         // a >> n = result (logical)
    Sar(BitsId, u32, BitsId),         // a >> n = result (arithmetic)
}

/// Type conversion operations
#[derive(Clone, Debug)]
pub enum ConvertOp {
    AsField(BitsId, FieldId),         // reinterpret bits as field
    AsUInt(BitsId, UIntId),           // reinterpret bits as uint
    AsBitsFromField(FieldId, BitsId), // reinterpret field as bits
    AsBitsFromUInt(UIntId, BitsId),   // reinterpret uint as bits
}

/// Witness creation operations
#[derive(Clone, Debug)]
pub enum WitnessOp {
    Field(FieldId, Word),             // create field witness
    UInt(UIntId, Word),               // create uint witness
    Bits(BitsId, Word),               // create bits witness
}

/// Assertion operations (type-agnostic)
#[derive(Clone, Debug)]
pub enum AssertOp {
    Eq(WitnessId, WitnessId, String), // assert a == b
    Zero(WitnessId, String),          // assert a == 0
}

/// Top-level operation enum with perfect 1-1 method mapping
#[derive(Clone, Debug)]
pub enum Operation {
    Field(FieldOp),
    UInt(UIntOp),
    Bits(BitsOp),
    Convert(ConvertOp),
    Witness(WitnessOp),
    Assert(AssertOp),
}

/// The Spark trait defines how high-level constructs map to constraints
pub trait Spark {
    /// Type representing the witness computation inputs
    type WitnessInput;
    /// Type representing the witness computation outputs  
    type WitnessOutput;
    
    /// Execute the witness computation
    fn compute_witness(input: &Self::WitnessInput) -> Self::WitnessOutput;
    
    /// Compile the computation into constraints
    fn compile_constraints(
        compiler: &mut compiler::ConstraintCompiler,
        input_ids: &Self::WitnessInput,
        output_ids: &Self::WitnessOutput,
    );
}