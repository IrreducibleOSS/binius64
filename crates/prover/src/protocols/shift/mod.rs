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

pub use prove::{OperatorData, prove};
pub use record::{build_record_for_bitmul_constraints, build_record_for_intmul_constraints};
