use binius_core::consts::WORD_SIZE_BITS;

use crate::{
	circuits::{
		bignum::BigUint,
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

	let mut acc = Secp256k1Affine::point_at_infinity(b);

	for bit_index in (0..bits).rev() {
		let limb = bit_index / WORD_SIZE_BITS;
		let bit = bit_index % WORD_SIZE_BITS;

		if bit_index != bits - 1 {
			acc = curve.double(b, &acc);
		}

		// TODO: this thing is somewhat inefficient but is dwarfed by curve ops
		//       ideally we should come up with a bit extraction gate
		let g_mult_bit = b.shl(g_mult.limbs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);
		let pk_mult_bit = b.shl(pk_mult.limbs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);

		// Addition implementation is complete (handles pai and doubling). When the mask
		// is zero, pai-to-pai support is needed. While the accumulator normally does not
		// assume the value of G or PK, such possibility cannot be ruled out.

		// TODO: optimize this to one addition per double-and-add step
		acc = curve.add(b, &acc, &g.pai_unless(b, g_mult_bit));
		acc = curve.add(b, &acc, &pk.pai_unless(b, pk_mult_bit));
	}

	acc
}
