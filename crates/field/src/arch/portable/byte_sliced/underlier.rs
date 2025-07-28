// Copyright 2025 Irreducible Inc.

use binius_utils::checked_arithmetics::checked_log_2;
use bytemuck::{Pod, Zeroable};
use rand::{
	Rng,
	distr::{Distribution, StandardUniform},
};

use crate::{
	Random,
	underlier::{ScaledUnderlier, UnderlierType},
};

/// Unerlier for byte-sliced fields. Even though it may seem to be equivalent to
/// `ScaledUnderlier<U, N>`, it is not. The difference is in order of bytes,
/// that's why this is a separate type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ByteSlicedUnderlier<U, const N: usize>(ScaledUnderlier<U, N>);

impl<U: Random, const N: usize> Distribution<ByteSlicedUnderlier<U, N>> for StandardUniform {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ByteSlicedUnderlier<U, N> {
		ByteSlicedUnderlier(rng.random())
	}
}

unsafe impl<U: Zeroable, const N: usize> Zeroable for ByteSlicedUnderlier<U, N> {}

unsafe impl<U: Pod, const N: usize> Pod for ByteSlicedUnderlier<U, N> {}

impl<U: UnderlierType + Pod, const N: usize> UnderlierType for ByteSlicedUnderlier<U, N> {
	const LOG_BITS: usize = U::LOG_BITS + checked_log_2(N);
}
