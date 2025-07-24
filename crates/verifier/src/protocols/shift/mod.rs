// Copyright 2025 Irreducible Inc.

pub const LOG_WORD_SIZE_BITS: usize = 6;
pub const WORD_SIZE_BITS: usize = 1 << LOG_WORD_SIZE_BITS;

mod error;
mod monster;
mod utils;
mod verify;

pub use monster::*;
pub use utils::*;
pub use verify::{OperatorData, verify};
