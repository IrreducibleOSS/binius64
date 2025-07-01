// Copyright 2024-2025 Irreducible Inc.

use super::packed_scaled::packed_scaled_field;
use crate::arch::packed_aes_256::*;

packed_scaled_field!(PackedAESBinaryField64x8b = [PackedAESBinaryField32x8b; 2]);
packed_scaled_field!(PackedAESBinaryField32x16b = [PackedAESBinaryField16x16b; 2]);
packed_scaled_field!(PackedAESBinaryField16x32b = [PackedAESBinaryField8x32b; 2]);
packed_scaled_field!(PackedAESBinaryField8x64b = [PackedAESBinaryField4x64b; 2]);
packed_scaled_field!(PackedAESBinaryField4x128b = [PackedAESBinaryField2x128b; 2]);
