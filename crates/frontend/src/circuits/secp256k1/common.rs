use crate::{
	circuits::bignum::{BigUint, PseudoMersennePrimeField},
	compiler::CircuitBuilder,
};

const N_LIMBS: usize = 4;

// Generator X coordinate, big endian.
const GX_BE: [u8; 32] = [
	0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
	0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
];

// Generator Y coordinate, big endian.
const GY_BE: [u8; 32] = [
	0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
	0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
];

pub fn coord_zero(b: &CircuitBuilder) -> BigUint {
	BigUint::new_constant(b, &num_bigint::BigUint::ZERO).zero_extend(b, N_LIMBS)
}

pub fn coord_b(b: &CircuitBuilder) -> BigUint {
	BigUint::new_constant(b, &num_bigint::BigUint::from(7usize)).zero_extend(b, N_LIMBS)
}

pub fn coords_gen(b: &CircuitBuilder) -> (BigUint, BigUint) {
	let x = BigUint::new_constant(b, &num_bigint::BigUint::from_bytes_be(&GX_BE));
	let y = BigUint::new_constant(b, &num_bigint::BigUint::from_bytes_be(&GY_BE));
	(x, y)
}

/// Coordinate prime field, of modulus `2^256 - 2^32 - 977`.
pub fn coord_field(b: &CircuitBuilder) -> PseudoMersennePrimeField {
	PseudoMersennePrimeField::new(b, 256, &[1 << 32 | 977])
}

/// Scalar prime field, of modulus equal to secp256k1 group size.
pub fn scalar_field(b: &CircuitBuilder) -> PseudoMersennePrimeField {
	PseudoMersennePrimeField::new(b, 256, &[0x402da1732fc9bebf, 0x4551231950b75fc4, 1])
}
