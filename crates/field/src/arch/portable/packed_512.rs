// Copyright 2024-2025 Irreducible Inc.

use super::packed_scaled::packed_scaled_field;
use crate::arch::packed_256::*;

packed_scaled_field!(PackedBinaryField512x1b = [PackedBinaryField256x1b; 2]);
packed_scaled_field!(PackedBinaryField256x2b = [PackedBinaryField128x2b; 2]);
packed_scaled_field!(PackedBinaryField128x4b = [PackedBinaryField64x4b; 2]);
packed_scaled_field!(PackedBinaryField64x8b = [PackedBinaryField32x8b; 2]);
packed_scaled_field!(PackedBinaryField32x16b = [PackedBinaryField16x16b; 2]);
packed_scaled_field!(PackedBinaryField16x32b = [PackedBinaryField8x32b; 2]);
packed_scaled_field!(PackedBinaryField8x64b = [PackedBinaryField4x64b; 2]);
packed_scaled_field!(PackedBinaryField4x128b = [PackedBinaryField2x128b; 2]);
