// Copyright 2024-2025 Irreducible Inc.

use cfg_if::cfg_if;

use crate::{
	ByteSlicedUnderlier, Field, PackedField,
	as_packed_field::{PackScalar, PackedType},
	underlier::WithUnderlier,
};

/// A trait to retrieve the optimal throughput `ordinal` packed field for a given architecture.
pub trait ArchOptimal: Field {
	type OptimalThroughputPacked: PackedField<Scalar = Self>
		+ WithUnderlier<Underlier = OptimalUnderlier>;
}

impl<F> ArchOptimal for F
where
	F: Field,
	OptimalUnderlier: PackScalar<F>,
{
	type OptimalThroughputPacked = PackedType<OptimalUnderlier, F>;
}

/// A trait to retrieve the optimal throughput packed byte-sliced field for a given architecture
pub trait ArchOptimalByteSliced: Field {
	type OptimalByteSliced: PackedField<Scalar = Self>
		+ WithUnderlier<Underlier = OptimalUnderlierByteSliced>;
}

impl<F> ArchOptimalByteSliced for F
where
	F: Field,
	OptimalUnderlierByteSliced: PackScalar<F>,
{
	type OptimalByteSliced = PackedType<OptimalUnderlierByteSliced, F>;
}

cfg_if! {
	if #[cfg(all(feature = "nightly_features", target_arch = "x86_64", target_feature = "avx512f"))] {
		pub const OPTIMAL_ALIGNMENT: usize = 512;

		pub type OptimalUnderlier128b = crate::arch::x86_64::m128::M128;
		pub type OptimalUnderlier256b = crate::arch::x86_64::m256::M256;
		pub type OptimalUnderlier512b = crate::arch::x86_64::m512::M512;
		pub type OptimalUnderlier = OptimalUnderlier512b;
	} else if #[cfg(all(feature = "nightly_features", target_arch = "x86_64", target_feature = "avx2"))] {
		use crate::underlier::ScaledUnderlier;

		pub const OPTIMAL_ALIGNMENT: usize = 256;

		pub type OptimalUnderlier128b = crate::arch::x86_64::m128::M128;
		pub type OptimalUnderlier256b = crate::arch::x86_64::m256::M256;
		pub type OptimalUnderlier512b = ScaledUnderlier<OptimalUnderlier256b, 2>;
		pub type OptimalUnderlier = OptimalUnderlier256b;
	} else if #[cfg(all(feature = "nightly_features", target_arch = "x86_64", target_feature = "sse2"))] {
		use crate::underlier::ScaledUnderlier;

		pub const OPTIMAL_ALIGNMENT: usize = 128;

		pub type OptimalUnderlier128b = crate::arch::x86_64::m128::M128;
		pub type OptimalUnderlier256b = ScaledUnderlier<OptimalUnderlier128b, 2>;
		pub type OptimalUnderlier512b = ScaledUnderlier<OptimalUnderlier256b, 2>;
		pub type OptimalUnderlier = OptimalUnderlier128b;
	} else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "aes"))] {
		use crate::underlier::ScaledUnderlier;

		pub const OPTIMAL_ALIGNMENT: usize = 128;

		pub type OptimalUnderlier128b = crate::arch::aarch64::m128::M128;
		pub type OptimalUnderlier256b = ScaledUnderlier<OptimalUnderlier128b, 2>;
		pub type OptimalUnderlier512b = ScaledUnderlier<OptimalUnderlier256b, 2>;
		pub type OptimalUnderlier = OptimalUnderlier128b;
	} else {
		use crate::underlier::ScaledUnderlier;

		pub const OPTIMAL_ALIGNMENT: usize = 128;

		pub type OptimalUnderlier128b = u128;
		pub type OptimalUnderlier256b = ScaledUnderlier<OptimalUnderlier128b, 2>;
		pub type OptimalUnderlier512b = ScaledUnderlier<OptimalUnderlier256b, 2>;
		pub type OptimalUnderlier = OptimalUnderlier128b;
	}
}

/// Optimal underlier for byte-sliced packed field for the current architecture.
/// This underlier can pack up to 128b scalars.
pub type OptimalUnderlierByteSliced = ByteSlicedUnderlier<OptimalUnderlier, 16>;
