use binius_core::word::Word;

use super::common::{coord_zero, coords_gen};
use crate::{
	circuits::bignum::BigUint,
	compiler::{CircuitBuilder, Wire},
};

/// Curve point in affine form - a tuple `(x, y)` that satisfies `y^2 = x^3 + 7`,
/// or `(0, 0)` for additive identity (point at infinity).
#[derive(Clone)]
pub struct Secp256k1Affine {
	pub x: BigUint,
	pub y: BigUint,
}

impl Secp256k1Affine {
	pub fn point_at_infinity(b: &CircuitBuilder) -> Self {
		let zero = coord_zero(b);
		Self {
			x: zero.clone(),
			y: zero,
		}
	}

	pub fn generator(b: &CircuitBuilder) -> Self {
		let (x, y) = coords_gen(b);
		Self { x, y }
	}

	pub fn is_point_at_infinity(&self, b: &CircuitBuilder) -> Wire {
		let x_zero = self.x.is_zero(b);
		let y_zero = self.y.is_zero(b);
		b.band(x_zero, y_zero)
	}

	pub fn to_jacobian(self, b: &CircuitBuilder) -> Secp256k1Jacobian {
		let pai_flag = self.is_point_at_infinity(b);

		let x = self.x;
		let mut y = self.y;
		let mut z = coord_zero(b);

		let y_first = y.limbs.first_mut().expect("N_LIMBS > 0");
		let z_first = z.limbs.first_mut().expect("N_LIMBS > 0");

		// Jacobian repr of PAI is (0, 1, 0)
		*y_first = b.bxor(*y_first, b.band(b.add_constant(Word::ONE), pai_flag));
		*z_first = b.band(b.add_constant(Word::ONE), b.bnot(pai_flag));

		Secp256k1Jacobian { x, y, z }
	}
}

/// Curve point in Jacobian form - a tuple `(x, y, z)` that corresponds to a tuple
/// `(x/z^2, y/z^3)` in affine form. Point-at-infinity has `z=0`, with canonical
/// representation being `(0, 1, 0)`.
#[derive(Clone)]
pub struct Secp256k1Jacobian {
	pub x: BigUint,
	pub y: BigUint,
	pub z: BigUint,
}

impl Secp256k1Jacobian {
	pub fn is_point_at_infinity(&self, b: &CircuitBuilder) -> Wire {
		self.z.is_zero(b)
	}
}
