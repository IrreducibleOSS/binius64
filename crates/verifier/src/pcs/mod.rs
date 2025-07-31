// Copyright 2025 Irreducible Inc.

pub mod error;
mod verifier;

pub use error::{Error, VerificationError};
pub use verifier::verify_transcript;
