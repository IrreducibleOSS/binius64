use binius_core::consts::WORD_SIZE_BITS;

use crate::{
	circuits::{
		bignum::{BigUint, select},
		secp256k1::{Secp256k1, Secp256k1Affine},
	},
	compiler::CircuitBuilder,
};

/// A common trick to save doublings when computing multiexponentiations of the form
/// `g*g_pow + pk*pk_pow` - instead of doing two scalar multiplications separately and
/// adding their results, we share the doubling step of double-and-add.
pub fn shamirs_trick(
	b: &CircuitBuilder,
	curve: &Secp256k1,
	bits: usize,
	g_mult: &BigUint,
	pk_mult: &BigUint,
	pk: Secp256k1Affine,
) -> Secp256k1Affine {
	let g = Secp256k1Affine::generator(b);
	let g_pk = curve.add(b, &g, &pk);

	let mut acc = Secp256k1Affine::point_at_infinity(b);

	for bit_index in (0..bits).rev() {
		let limb = bit_index / WORD_SIZE_BITS;
		let bit = bit_index % WORD_SIZE_BITS;

		if bit_index != bits - 1 {
			acc = curve.double(b, &acc);
		}

		let g_mult_bit = b.shl(g_mult.limbs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);
		let pk_mult_bit = b.shl(pk_mult.limbs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);

		// A 3-to-1 mux
		let x = select(b, &g.x, &select(b, &pk.x, &g_pk.x, g_mult_bit), pk_mult_bit);
		let y = select(b, &g.y, &select(b, &pk.y, &g_pk.y, g_mult_bit), pk_mult_bit);

		// Point at infinity flag is a single wire, allowing us to save a BigUint select.
		let is_point_at_infinity = b.band(b.bnot(g_mult_bit), b.bnot(pk_mult_bit));

		// Addition implementation is complete (handles pai and doubling). When the mask
		// is zero, pai-to-pai support is needed. While the accumulator normally does not
		// assume the value of G or PK, such possibility cannot be ruled out.
		acc = curve.add(
			b,
			&acc,
			&Secp256k1Affine {
				x,
				y,
				is_point_at_infinity,
			},
		);
	}

	acc
}
