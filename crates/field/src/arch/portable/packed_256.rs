// Copyright 2023-2025 Irreducible Inc.

use super::packed_scaled::packed_scaled_field;
use crate::{
	PackedBinaryField1x128b, PackedBinaryField2x64b, PackedBinaryField4x32b,
	PackedBinaryField8x16b, PackedBinaryField16x8b, PackedBinaryField32x4b, PackedBinaryField64x2b,
	PackedBinaryField128x1b,
};

packed_scaled_field!(PackedBinaryField256x1b = [PackedBinaryField128x1b; 2]);
packed_scaled_field!(PackedBinaryField128x2b = [PackedBinaryField64x2b; 2]);
packed_scaled_field!(PackedBinaryField64x4b = [PackedBinaryField32x4b; 2]);
packed_scaled_field!(PackedBinaryField32x8b = [PackedBinaryField16x8b; 2]);
packed_scaled_field!(PackedBinaryField16x16b = [PackedBinaryField8x16b; 2]);
packed_scaled_field!(PackedBinaryField8x32b = [PackedBinaryField4x32b; 2]);
packed_scaled_field!(PackedBinaryField4x64b = [PackedBinaryField2x64b; 2]);
packed_scaled_field!(PackedBinaryField2x128b = [PackedBinaryField1x128b; 2]);
