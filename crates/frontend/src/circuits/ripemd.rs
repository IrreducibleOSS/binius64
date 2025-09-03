use crate::compiler::{CircuitBuilder, Wire};

/// Computes the RIPEMD-160 compression function on a single 512-bit block.
///
/// This function implements the core compression function of RIPEMD-160, which processes
/// a single 512-bit (64-byte) message block and updates the 160-bit internal state.
///
/// # Arguments
/// * `builder` - Circuit builder for constructing constraints
/// * `state` - Current hash state as 5 wires, each containing a 32-bit word in the low 32 bits
///   (high 32 bits must be zero). The state words are in little-endian byte order.
/// * `message_block` - Message block as 16 wires, each containing a 32-bit word in the low 32 bits
///   (high 32 bits must be zero). The words are in little-endian byte order.
///
/// # Returns
/// * `[Wire; 5]` - Updated hash state as 5 wires, each containing a 32-bit word in the low 32 bits
///   (high 32 bits are zero). The state words are in little-endian byte order.
///
/// # Preconditions
/// * All input wires must have their high 32 bits set to zero (i.e., `wire & 0xFFFFFFFF == wire`)
/// * This is the caller's responsibility to ensure
///
/// # Implementation Notes
/// * RIPEMD-160 uses two parallel computation paths (left and right lines) that are combined
/// * Each line performs 80 rounds (5 groups of 16 rounds each)
/// * The final state is computed by adding the results of both lines to the input state
pub fn ripemd160_compress(
	builder: &CircuitBuilder,
	state: [Wire; 5],
	message_block: [Wire; 16],
) -> [Wire; 5] {
	// Constants for left line rounds
	const KL: [u32; 5] = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];

	// Constants for right line rounds
	const KR: [u32; 5] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

	// Message permutation for left line
	const ZL: [usize; 80] = [
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // rounds 0-15
		1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, // rounds 16-31
		5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, // rounds 32-47
		0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9, // rounds 48-63
		7, 3, 15, 11, 0, 12, 4, 8, 5, 1, 13, 9, 6, 2, 14, 10, // rounds 64-79
	];

	// Message permutation for right line
	const ZR: [usize; 80] = [
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, // rounds 0-15
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, // rounds 16-31
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, // rounds 32-47
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, // rounds 48-63
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11, // rounds 64-79
	];

	// Rotation amounts for left line
	const SL: [u32; 80] = [
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, // rounds 0-15
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, // rounds 16-31
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, // rounds 32-47
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, // rounds 48-63
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6, // rounds 64-79
	];

	// Rotation amounts for right line
	const SR: [u32; 80] = [
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, // rounds 0-15
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, // rounds 16-31
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, // rounds 32-47
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, // rounds 48-63
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11, // rounds 64-79
	];

	// Initialize working variables for left line
	let mut al = state[0];
	let mut bl = state[1];
	let mut cl = state[2];
	let mut dl = state[3];
	let mut el = state[4];

	// Initialize working variables for right line
	let mut ar = state[0];
	let mut br = state[1];
	let mut cr = state[2];
	let mut dr = state[3];
	let mut er = state[4];

	// Process 80 rounds for each line
	for round_num in 0..80 {
		let round_group = round_num / 16;

		// Left line
		let func_l = match round_group {
			0 => f,
			1 => g,
			2 => h,
			3 => i,
			4 => j,
			_ => unreachable!(),
		};

		let (new_al, new_cl) = round(
			builder,
			al,
			bl,
			cl,
			dl,
			el,
			message_block[ZL[round_num]],
			SL[round_num],
			KL[round_group],
			func_l,
		);

		// Rotate variables for left line
		al = el;
		el = dl;
		dl = new_cl;
		cl = bl;
		bl = new_al;

		// Right line
		let func_r = match round_group {
			0 => j,
			1 => i,
			2 => h,
			3 => g,
			4 => f,
			_ => unreachable!(),
		};

		let (new_ar, new_cr) = round(
			builder,
			ar,
			br,
			cr,
			dr,
			er,
			message_block[ZR[round_num]],
			SR[round_num],
			KR[round_group],
			func_r,
		);

		// Rotate variables for right line
		ar = er;
		er = dr;
		dr = new_cr;
		cr = br;
		br = new_ar;
	}

	// Combine results: state[i] = state[i] + cl + dr (and appropriate permutation)
	[
		builder.iadd_32(builder.iadd_32(state[1], cl), dr),
		builder.iadd_32(builder.iadd_32(state[2], dl), er),
		builder.iadd_32(builder.iadd_32(state[3], el), ar),
		builder.iadd_32(builder.iadd_32(state[4], al), br),
		builder.iadd_32(builder.iadd_32(state[0], bl), cr),
	]
}

// Selection function f(x, y, z) = x XOR y XOR z
fn f(b: &CircuitBuilder, x: Wire, y: Wire, z: Wire) -> Wire {
	b.bxor(b.bxor(x, y), z)
}

// Selection function g(x, y, z) = (x AND y) OR (NOT x AND z) = z XOR (x AND (y XOR z))
fn g(b: &CircuitBuilder, x: Wire, y: Wire, z: Wire) -> Wire {
	b.bxor(z, b.band(x, b.bxor(y, z)))
}

// Selection function h(x, y, z) = (x OR NOT y) XOR z
fn h(b: &CircuitBuilder, x: Wire, y: Wire, z: Wire) -> Wire {
	// where NOT y in 32-bit context means y XOR 0xFFFFFFFF
	let not_y = b.bxor(y, b.add_constant_64(0xFFFFFFFF));
	b.bxor(b.bor(x, not_y), z)
}

// Selection function i(x, y, z) = (x AND z) OR (y AND NOT z) = y XOR (z AND (x XOR y))
fn i(b: &CircuitBuilder, x: Wire, y: Wire, z: Wire) -> Wire {
	b.bxor(y, b.band(z, b.bxor(x, y)))
}

// Selection function j(x, y, z) = x XOR (y OR NOT z)
fn j(b: &CircuitBuilder, x: Wire, y: Wire, z: Wire) -> Wire {
	// where NOT z in 32-bit context means z XOR 0xFFFFFFFF
	let not_z = b.bxor(z, b.add_constant_64(0xFFFFFFFF));
	b.bxor(x, b.bor(y, not_z))
}

// RIPEMD-160 round function
#[allow(clippy::too_many_arguments)]
fn round(
	b: &CircuitBuilder,
	a: Wire,
	b_val: Wire,
	c: Wire,
	d: Wire,
	e: Wire,
	x: Wire,
	s: u32,
	k: u32,
	func: fn(&CircuitBuilder, Wire, Wire, Wire) -> Wire,
) -> (Wire, Wire) {
	// T = A + func(B, C, D) + X + K
	let f_val = func(b, b_val, c, d);
	let t1 = b.iadd_32(a, f_val);
	let t2 = b.iadd_32(t1, x);
	let t = b.iadd_32(t2, b.add_constant_64(k as u64));

	// T = (T << s) | (T >> (32 - s)) (rotate left by s)
	let t_rot = b.rotl_32(t, s);

	// T = T + E
	let t_final = b.iadd_32(t_rot, e);

	// Return new A and new C (which is old B rotated left by 10)
	(t_final, b.rotl_32(b_val, 10))
}
