// Copyright 2025 Irreducible Inc.

mod error;
mod fat_multilinear;
mod key_collection;
use binius_verifier::protocols::shift::{BITAND_ARITY, INTMUL_ARITY, SHIFT_VARIANT_COUNT};
mod phase_1;
pub use fat_multilinear::*;
pub use key_collection::*;
