// Copyright 2024-2025 Irreducible Inc.

pub mod montgomery_mul;

#[cfg(all(target_feature = "sse2", target_feature = "pclmulqdq"))]
mod m128;
#[cfg(all(target_feature = "avx2", target_feature = "vpclmulqdq"))]
mod m256;
#[cfg(all(target_feature = "avx512f", target_feature = "vpclmulqdq"))]
mod m512;
