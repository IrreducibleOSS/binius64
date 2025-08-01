// Copyright 2025 Irreducible Inc.

pub const SHIFT_VARIANT_COUNT: usize = 3;

pub const BITMUL_ARITY: usize = 3;
pub const INTMUL_ARITY: usize = 4;

mod error;
mod monster;
mod utils;
mod verify;

pub use monster::*;
pub use utils::*;
pub use verify::{OperatorData, verify};
