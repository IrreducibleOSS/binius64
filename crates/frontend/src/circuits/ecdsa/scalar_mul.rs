use binius_core::consts::WORD_SIZE_BITS;

use crate::{
	circuits::{
		bignum::{BigUint, biguint_eq, select as select_biguint},
		secp256k1::{
			N_LIMBS, Secp256k1, Secp256k1Affine, coord_lambda, coord_zero,
			select as select_secp256k1_affine,
		},
	},
	compiler::{CircuitBuilder, Wire},
};

/// A common trick to save doublings when computing multiexponentiations of the form
/// `G*g_mult + PK*pk_mult` - instead of doing two scalar multiplications separately and
/// adding their results, we share the doubling step of double-and-add.
///
/// For secp256k1, we can go one step further: the curve has an endomorphism `λ (x, y) = (βx, y)`
/// where `λ³=1 (mod n)` and `β³=1 (mod p)` (`n` being the scalar field modulus and `p` coordinate
/// field one). For a 256-bit scalar `k` it is possible to split it into `k1` and `k2` such that
/// `k1 + λ k2 = k (mod n)` and both `k1` and `k2` are no farther than `2^128` from zero.
///
/// Using the above fact, we can "split" both the G and PK 256-bit multiplier scalars into a total
/// of four 128-bit subscalars. Instead of 4-wide lookup in `shamirs_trick_naive`, we do a 16-wide
/// lookup for all subset sums of `{G, G_endo, PK, PK_endo}`, where `*_endo` points are obtained via
/// endomorphism. This halves the total number of doublings and additions at a cost of a larger
/// precomputation, but the eventual savings are still in the order of 2x.
///
/// Returns `G*g_mult + PK*pk_mult` and an MSB-bool indicating the correctness of endomorphism
/// splits.
pub fn shamirs_trick_endomorphism(
	b: &CircuitBuilder,
	curve: &Secp256k1,
	g_mult: &BigUint,
	pk_mult: &BigUint,
	pk: Secp256k1Affine,
) -> (Secp256k1Affine, Wire) {
	assert_eq!(g_mult.limbs.len(), N_LIMBS);
	assert_eq!(pk_mult.limbs.len(), N_LIMBS);

	// Nondeterministically split both scalars, constrain the splits
	let (g1_mult_neg, g2_mult_neg, g1_mult_abs, g2_mult_abs) =
		b.secp256k1_endomorphism_split_hint(&g_mult.limbs);

	let g_endo_ok = check_endomorphism_split(
		b,
		curve,
		g1_mult_neg,
		g2_mult_neg,
		g1_mult_abs,
		g2_mult_abs,
		g_mult,
	);

	let (pk1_mult_neg, pk2_mult_neg, pk1_mult_abs, pk2_mult_abs) =
		b.secp256k1_endomorphism_split_hint(&pk_mult.limbs);

	let pk_endo_ok = check_endomorphism_split(
		b,
		curve,
		pk1_mult_neg,
		pk2_mult_neg,
		pk1_mult_abs,
		pk2_mult_abs,
		pk_mult,
	);

	// Compute the endomorphisms
	let g = Secp256k1Affine::generator(b);
	let g_endo = curve.endomorphism(b, &g);
	let pk_endo = curve.endomorphism(b, &pk);

	// The split returns "signed scalars" (which is required to fit them into 128 bits).
	// Negate the base if needed to only care about positive exponents.
	let g1 = curve.negate_if(b, g1_mult_neg, &g);
	let g2 = curve.negate_if(b, g2_mult_neg, &g_endo);

	let pk1 = curve.negate_if(b, pk1_mult_neg, &pk);
	let pk2 = curve.negate_if(b, pk2_mult_neg, &pk_endo);

	// Compute subset sums of {G, G_endo, PK, PK_endo} using a total of 11 additions
	let mut lookup = Vec::with_capacity(16);
	lookup.push(Secp256k1Affine::point_at_infinity(b));
	for (i, pt) in [g1, g2, pk1, pk2].into_iter().enumerate() {
		lookup.push(pt.clone());
		for j in 1..1 << i {
			lookup.push(curve.add_incomplete(b, &lookup[j], &pt));
		}
	}

	let mut acc = Secp256k1Affine::point_at_infinity(b);

	for bit_index in (0..128).rev() {
		let limb = bit_index / WORD_SIZE_BITS;
		let bit = bit_index % WORD_SIZE_BITS;

		if bit_index != 127 {
			acc = curve.double(b, &acc);
		}

		// This is essentially an inlined multi wire multiplexer, but due to the fact
		// it uses affine point conditional selections and separate wires instead of masks
		// it's simpler to inline it there.
		// TODO: replace it with a multiplexer once the abstraction is mature enough
		let g1_mult_bit = b.shl(g1_mult_abs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);
		let g2_mult_bit = b.shl(g2_mult_abs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);
		let pk1_mult_bit = b.shl(pk1_mult_abs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);
		let pk2_mult_bit = b.shl(pk2_mult_abs[limb], (WORD_SIZE_BITS - 1 - bit) as u32);

		let mut level = lookup.clone();
		for sel_bit in [g1_mult_bit, g2_mult_bit, pk1_mult_bit, pk2_mult_bit] {
			let next_level = level
				.chunks(2)
				.map(|pair| {
					assert_eq!(pair.len(), 2);
					select_secp256k1_affine(b, sel_bit, &pair[1], &pair[0])
				})
				.collect();

			level = next_level;
		}

		assert_eq!(level.len(), 1);
		acc = curve.add_incomplete(b, &acc, &level[0]);
	}

	(acc, b.band(g_endo_ok, pk_endo_ok))
}

// Constrain the return value of `CircuitBuilder::secp256k1_endomorphism_split_hint`.
// Verifies that `k1 + λ k2 = k (mod n)` where `n` is scalar field modulus.
fn check_endomorphism_split(
	b: &CircuitBuilder,
	curve: &Secp256k1,
	k1_neg: Wire,
	k2_neg: Wire,
	k1_abs: [Wire; 2],
	k2_abs: [Wire; 2],
	k: &BigUint,
) -> Wire {
	assert_eq!(k.limbs.len(), N_LIMBS);

	let k1_abs = BigUint {
		limbs: k1_abs.to_vec(),
	}
	.zero_extend(b, N_LIMBS);
	let k2_abs = BigUint {
		limbs: k2_abs.to_vec(),
	}
	.zero_extend(b, N_LIMBS);

	let f_scalar = curve.f_scalar();
	let k1 = select_biguint(b, k1_neg, &f_scalar.sub(b, &coord_zero(b), &k1_abs), &k1_abs);
	let k2 = select_biguint(b, k2_neg, &f_scalar.sub(b, &coord_zero(b), &k2_abs), &k2_abs);

	biguint_eq(b, k, &f_scalar.add(b, &k1, &f_scalar.mul(b, &k2, &coord_lambda(b))))
}

/// A common trick to save doublings when computing multiexponentiations of the form
/// `G*g_mult + PK*pk_mult` - instead of doing two scalar multiplications separately and
/// adding their results, we share the doubling step of double-and-add.
///
/// This implementation relies on group axioms only. It is currently unused for secp256k1
/// but may prove useful for other curves.
#[allow(unused)]
pub fn shamirs_trick_naive(
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
		let x =
			select_biguint(b, pk_mult_bit, &select_biguint(b, g_mult_bit, &g_pk.x, &pk.x), &g.x);
		let y =
			select_biguint(b, pk_mult_bit, &select_biguint(b, g_mult_bit, &g_pk.y, &pk.y), &g.y);

		// Point at infinity flag is a single wire, allowing us to save a BigUint select.
		let is_point_at_infinity = b.band(b.bnot(g_mult_bit), b.bnot(pk_mult_bit));

		// Addition implementation is incomplete (it handles pai, but not doubling). When
		// the mask is zero, pai-to-pai support is needed. The probability of accumulator
		// assuming value G, PK, or G+PK at any point in the computation is vanishingly low.
		// We assert false in this case, resulting in a completeness gap.
		acc = curve.add_incomplete(
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
