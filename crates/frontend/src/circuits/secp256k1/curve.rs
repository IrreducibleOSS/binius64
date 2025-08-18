use binius_core::word::Word;

use super::{
	common::{coord_b, coord_field, scalar_field},
	point::{Secp256k1Affine, Secp256k1Jacobian},
};
use crate::{
	circuits::bignum::{BigUint, PseudoMersennePrimeField, assert_eq, xor},
	compiler::CircuitBuilder,
};

/// Secp256k1 - a short Weierstrass elliptic curve of the form `y^2 = x^3 + 7` over
/// the prime field of modulus `2^256 - 2^32 - 977`.
pub struct Secp256k1 {
	f_p: PseudoMersennePrimeField,
	f_scalar: PseudoMersennePrimeField,
	b: BigUint,
}

impl Secp256k1 {
	pub fn new(b: &CircuitBuilder) -> Self {
		let f_p = coord_field(b);
		let f_scalar = scalar_field(b);
		let b = coord_b(b);
		Self { f_p, f_scalar, b }
	}

	pub fn f_p(&self) -> &PseudoMersennePrimeField {
		&self.f_p
	}

	pub fn f_scalar(&self) -> &PseudoMersennePrimeField {
		&self.f_scalar
	}

	pub fn assert_affine_on_curve(&self, b: &CircuitBuilder, affine: &Secp256k1Affine) {
		let f_p = &self.f_p;

		let x_pow2 = f_p.square(b, &affine.x);
		let x_pow3 = f_p.mul(b, &x_pow2, &affine.x);

		let y_pow2 = f_p.square(b, &affine.y);
		assert_eq(b, "secp256k1_on_curve", &y_pow2, &f_p.add(b, &x_pow3, &self.b));
	}

	pub fn jacobian_to_affine(
		&self,
		b: &CircuitBuilder,
		jacobian: Secp256k1Jacobian,
	) -> Secp256k1Affine {
		let f_p = &self.f_p;
		let pai_flag = jacobian.is_point_at_infinity(b);
		let not_pai_flag = b.bnot(pai_flag);

		let z_inverse = f_p.inverse(b, &jacobian.z, not_pai_flag);
		let z_inverse_pow2 = f_p.square(b, &z_inverse);
		let z_inverse_pow3 = f_p.mul(b, &z_inverse_pow2, &z_inverse);

		let x = f_p
			.mul(b, &jacobian.x, &z_inverse_pow2)
			.mask(b, not_pai_flag);
		let y = f_p
			.mul(b, &jacobian.y, &z_inverse_pow3)
			.mask(b, not_pai_flag);
		Secp256k1Affine { x, y }
	}

	pub fn double(&self, b: &CircuitBuilder, p: &Secp256k1Jacobian) -> Secp256k1Jacobian {
		// Cost: 2M + 5S + 6add + 3*2 + 1*3 + 1*8
		// https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
		let f_p = &self.f_p;

		let Secp256k1Jacobian {
			x: x1,
			y: y1,
			z: z1,
		} = p;

		// C = X1^2
		// D = Y1^2
		// E = D^2
		// F = 2*((X1+D)^2-C-E)
		// G = 3*C
		// H = G^2
		// X3 = H-2*F
		// Y3 = G*(F-X3)-8*E
		// Z3 = 2*Y1*Z1

		// NB: Z1 == 0 => Z3 == 0 means doubling works correctly with PAI.

		let c = f_p.square(b, x1);
		let d = f_p.square(b, y1);
		let e = f_p.square(b, &d);
		let f_half = f_p.sub(b, &f_p.sub(b, &f_p.square(b, &f_p.add(b, &p.x, &d)), &c), &e);
		let f = f_p.add(b, &f_half, &f_half);
		let g = f_p.add(b, &f_p.add(b, &c, &c), &c);
		let h = f_p.square(b, &g);

		let x3 = f_p.sub(b, &h, &f_p.add(b, &f, &f));
		let e_by_2 = f_p.add(b, &e, &e);
		let e_by_4 = f_p.add(b, &e_by_2, &e_by_2);
		let e_by_8 = f_p.add(b, &e_by_4, &e_by_4);
		let y3 = f_p.sub(b, &f_p.mul(b, &g, &f_p.sub(b, &f, &x3)), &e_by_8);
		let z3_half = f_p.mul(b, &p.y, z1);
		let z3 = f_p.add(b, &z3_half, &z3_half);

		Secp256k1Jacobian {
			x: x3,
			y: y3,
			z: z3,
		}
	}

	pub fn add(
		&self,
		b: &CircuitBuilder,
		p1: &Secp256k1Jacobian,
		p2: &Secp256k1Jacobian,
	) -> Secp256k1Jacobian {
		let f_p = &self.f_p;

		let Secp256k1Jacobian {
			x: x1,
			y: y1,
			z: z1,
		} = p1;
		let Secp256k1Jacobian {
			x: x2,
			y: y2,
			z: z2,
		} = p2;

		// Cost: 11M + 5S + 9add + 4*2
		// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
		//   Z1Z1 = Z1^2
		//   Z2Z2 = Z2^2
		//   U1 = X1*Z2Z2
		//   U2 = X2*Z1Z1
		//   S1 = Y1*Z2*Z2Z2
		//   S2 = Y2*Z1*Z1Z1
		//   H = U2-U1
		//   I = (2*H)^2
		//   J = H*I
		//   r = 2*(S2-S1)
		//   V = U1*I
		//   X3 = r^2-J-2*V
		//   Y3 = r*(V-X3)-2*S1*J
		//   Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H

		let z1z1 = f_p.square(b, z1);
		let z2z2 = f_p.square(b, z2);
		let u1 = f_p.mul(b, x1, &z2z2);
		let u2 = f_p.mul(b, x2, &z1z1);
		let s1 = f_p.mul(b, &f_p.mul(b, y1, z2), &z2z2);
		let s2 = f_p.mul(b, &f_p.mul(b, y2, z1), &z1z1);
		let h = f_p.sub(b, &u2, &u1);
		let i = f_p.square(b, &f_p.add(b, &h, &h));
		let j = f_p.mul(b, &h, &i);
		let r_half = f_p.sub(b, &s2, &s1);
		let r = f_p.add(b, &r_half, &r_half);
		let v = f_p.mul(b, &u1, &i);
		let x3 = f_p.sub(b, &f_p.sub(b, &f_p.square(b, &r), &j), &f_p.add(b, &v, &v));
		let s1j = f_p.mul(b, &s1, &j);
		let s1j_by_2 = f_p.add(b, &s1j, &s1j);
		let y3 = f_p.sub(b, &f_p.mul(b, &r, &f_p.sub(b, &v, &x3)), &s1j_by_2);
		let z3 = f_p.mul(
			b,
			&f_p.sub(b, &f_p.sub(b, &f_p.square(b, &f_p.add(b, z1, z2)), &z1z1), &z2z2),
			&h,
		);

		// The formulas above are correct for valid and unequal curve points
		// only. We need to handle additive identity and doubling separately.

		let pai_1 = p1.is_point_at_infinity(b);
		let pai_2 = p2.is_point_at_infinity(b);

		let is_identity = b.bor(b.band(pai_1, b.bnot(pai_2)), b.band(b.bnot(pai_1), pai_2));
		let is_any_pai = b.bor(pai_1, pai_2);
		let is_both_pai = b.band(pai_1, pai_2);
		let is_none_pai = b.bnot(is_any_pai);

		// Adding identity (would return zero for both addends being PAI).
		let x_i = xor(b, &x1.mask(b, pai_2), &x2.mask(b, pai_1));
		let y_i = xor(b, &y1.mask(b, pai_2), &y2.mask(b, pai_1));
		let z_i = xor(b, &z1.mask(b, pai_2), &z2.mask(b, pai_1));

		// Doubling case.
		let Secp256k1Jacobian {
			x: x_dbl,
			y: y_dbl,
			z: z_dbl,
		} = self.double(b, p1);

		// Selecting the correct outcome.
		let u_diff = f_p.sub(b, &u1, &u2);
		let s_diff = f_p.sub(b, &s1, &s2);

		let u_same = u_diff.is_zero(b);
		let s_same = s_diff.is_zero(b);

		let is_dbl = b.band(u_same, s_same);
		let is_pai_res = b.band(u_same, b.bnot(s_same));
		let is_unequal = b.bnot(u_same);

		let is_dbl = b.band(is_dbl, is_none_pai);
		let is_unequal = b.band(is_unequal, is_none_pai);

		let x = xor(
			b,
			&xor(b, &x3.mask(b, is_unequal), &x_dbl.mask(b, is_dbl)),
			&x_i.mask(b, is_identity),
		);
		let y = xor(
			b,
			&xor(b, &y3.mask(b, is_unequal), &y_dbl.mask(b, is_dbl)),
			&y_i.mask(b, is_identity),
		);
		let z = xor(
			b,
			&xor(b, &z3.mask(b, is_unequal), &z_dbl.mask(b, is_dbl)),
			&z_i.mask(b, is_identity),
		);

		let is_pai_res = b.bor(b.band(is_pai_res, is_none_pai), is_both_pai);

		// Return canonical repr if the result is PAI.
		let mut y = y;
		let y_first = y.limbs.first_mut().expect("N_LIMBS > 0");
		*y_first = b.bxor(*y_first, b.band(b.add_constant(Word::ONE), is_pai_res));

		Secp256k1Jacobian { x, y, z }
	}
}
