// Copyright 2025 Irreducible Inc.

pub const SHIFT_VARIANT_COUNT: usize = 3;
pub const BITAND_ARITY: usize = 3;
pub const INTMUL_ARITY: usize = 4;
pub const ZERO_ARITY: usize = 1;

mod monster;

pub use monster::*;
mod error;
mod verify;

pub use error::Error;
pub use verify::{OperatorData, verify};
