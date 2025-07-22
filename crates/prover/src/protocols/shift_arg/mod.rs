// Copyright 2025 Irreducible Inc.

mod error;
mod prove;

pub use error::Error;
pub use prove::prove;

#[cfg(test)]
pub mod tests;
