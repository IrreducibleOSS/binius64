// Copyright 2024-2025 Irreducible Inc.

use super::packed_scaled::packed_scaled_field;
use crate::{
	PackedAESBinaryField1x128b, PackedAESBinaryField2x64b, PackedAESBinaryField4x32b,
	PackedAESBinaryField8x16b, PackedAESBinaryField16x8b,
};

packed_scaled_field!(PackedAESBinaryField32x8b = [PackedAESBinaryField16x8b; 2]);
packed_scaled_field!(PackedAESBinaryField16x16b = [PackedAESBinaryField8x16b; 2]);
packed_scaled_field!(PackedAESBinaryField8x32b = [PackedAESBinaryField4x32b; 2]);
packed_scaled_field!(PackedAESBinaryField4x64b = [PackedAESBinaryField2x64b; 2]);
packed_scaled_field!(PackedAESBinaryField2x128b = [PackedAESBinaryField1x128b; 2]);
