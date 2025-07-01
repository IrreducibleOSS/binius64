// Copyright 2025 Irreducible Inc.
// The code is initially based on `maybe-rayon` crate, https://github.com/shssoichiro/maybe-rayon

mod parallel_slice;
mod parallel_slice_mut;

pub use parallel_slice::ParallelSlice;
pub use parallel_slice_mut::ParallelSliceMut;
