// Copyright 2024-2025 Irreducible Inc.

//! Efficient implementations of the binary field additive NTT.
//!
//! See [LCH14] and [DP24] Section 2.3 for mathematical background.
//!
//! [LCH14]: <https://arxiv.org/abs/1404.3458>
//! [DP24]: <https://eprint.iacr.org/2024/504>

mod additive_ntt;
mod error;
mod multithreaded;
mod odd_interpolate;
mod single_threaded;
#[cfg(test)]
mod tests;
pub mod twiddle;

pub use additive_ntt::{AdditiveNTT, NTTShape};
pub use error::Error;
pub use multithreaded::MultithreadedNTT;
pub use odd_interpolate::OddInterpolate;
pub use single_threaded::SingleThreadedNTT;
