// Copyright 2025 Irreducible Inc.

mod error;
mod monster;
mod phase_1;
mod phase_2;
mod prove;
mod record;
pub mod utils;

#[cfg(test)]
pub mod tests;

use binius_verifier::protocols::shift::{BITMUL_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT};
pub use prove::{OperatorData, prove};
pub use record::build_prover_constraint_system;
