//! Error types for the predicate compiler

use crate::{predicate::PredicateId, witness::WitnessVar};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("Cyclic dependency detected in witness graph")]
    CyclicDependency,
    
    #[error("Missing witness value for variable {var:?}")]
    MissingWitness { var: WitnessVar },
    
    #[error("Conflicting definitions for witness variable {var:?}")]
    ConflictingDefinitions { var: WitnessVar },
    
    #[error("Predicate {id:?} references undefined witness variables")]
    UndefinedWitnesses { id: PredicateId },
    
    #[error("Failed to compile witness recipe: {reason}")]
    RecipeCompilation { reason: String },
    
    #[error("Invalid shift amount: {amount} (must be < 64)")]
    InvalidShiftAmount { amount: u8 },
    
    #[error("Witness computation failed: {reason}")]
    WitnessComputation { reason: String },
}

pub type Result<T> = std::result::Result<T, CompilerError>;