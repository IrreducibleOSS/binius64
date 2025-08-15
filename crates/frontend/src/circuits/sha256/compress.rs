use binius_core::word::Word;

use crate::compiler::{CircuitBuilder, Wire};

const IV: [u32; 8] = [
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The internal state of SHA-256.
///
/// The state size is 256 bits. For efficiency reasons it's packed in 8 x 32-bit words, and not
/// 4 x 64-bit words.
///
/// The elements are referred to as a–h or H0–H7.
#[derive(Clone)]
pub struct State(pub [Wire; 8]);

impl State {
	pub fn new(wires: [Wire; 8]) -> Self {
		State(wires)
	}

	pub fn public(builder: &CircuitBuilder) -> Self {
		State(std::array::from_fn(|_| builder.add_inout()))
	}

	pub fn private(builder: &CircuitBuilder) -> Self {
		State(std::array::from_fn(|_| builder.add_witness()))
	}

	pub fn iv(builder: &CircuitBuilder) -> Self {
		State(std::array::from_fn(|i| builder.add_constant(Word(IV[i] as u64))))
	}

	/// Packs the state into 4 x 64-bit words.
	pub fn pack_4x64b(&self, builder: &CircuitBuilder) -> [Wire; 4] {
		fn pack_pair(b: &CircuitBuilder, hi: Wire, lo: Wire) -> Wire {
			b.bxor(lo, b.shl(hi, 32))
		}

		[
			pack_pair(builder, self.0[0], self.0[1]),
			pack_pair(builder, self.0[2], self.0[3]),
			pack_pair(builder, self.0[4], self.0[5]),
			pack_pair(builder, self.0[6], self.0[7]),
		]
	}
}

/// SHA-256 compress function.
pub struct Compress {
	pub state_in: State,
	pub state_out: State,
	pub m: [Wire; 16],
}

impl Compress {
	pub fn new(builder: &CircuitBuilder, state_in: State, m: [Wire; 16]) -> Self {
		// ---- message-schedule ----
		// W[0..15] = block_words & M32
		// for t = 16 .. 63:
		//     s0   = σ0(W[t-15])
		//     s1   = σ1(W[t-2])
		//     (p, _)  = Add32(W[t-16], s0)
		//     (q, _)  = Add32(p, W[t-7])
		//     (W[t],_) = Add32(q, s1)
		let m32 = builder.add_constant(Word::MASK_32);
		let m_masked: [Wire; 16] = std::array::from_fn(|i| builder.band(m[i], m32));

		let mut w: Vec<Wire> = Vec::with_capacity(64);

		// W[0..15] = block_words & M32
		w.extend_from_slice(&m_masked);

		// W[16..63] computed from previous W values
		for t in 16..64 {
			let s0 = small_sigma_0(builder, w[t - 15]);
			let s1 = small_sigma_1(builder, w[t - 2]);
			let p = builder.iadd_32(w[t - 16], s0);
			let q = builder.iadd_32(p, w[t - 7]);
			w.push(builder.iadd_32(q, s1));
		}

		let w: &[Wire; 64] = (&*w).try_into().unwrap();
		let mut state = state_in.clone();
		for t in 0..64 {
			state = round(builder, t, state, w);
		}

		// Add the compressed chunk to the current hash value
		let state_out = State([
			builder.iadd_32(state_in.0[0], state.0[0]),
			builder.iadd_32(state_in.0[1], state.0[1]),
			builder.iadd_32(state_in.0[2], state.0[2]),
			builder.iadd_32(state_in.0[3], state.0[3]),
			builder.iadd_32(state_in.0[4], state.0[4]),
			builder.iadd_32(state_in.0[5], state.0[5]),
			builder.iadd_32(state_in.0[6], state.0[6]),
			builder.iadd_32(state_in.0[7], state.0[7]),
		]);

		Compress {
			state_in,
			state_out,
			m,
		}
	}

	pub fn populate_m(&self, w: &mut crate::compiler::circuit::WitnessFiller, m: [u8; 64]) {
		debug_assert_eq!(self.m.len(), 16);

		for i in 0..16 {
			let j = i * 4;
			// Assemble a 32-bit big-endian word and widen to 64 bits.
			let limb = ((m[j] as u64) << 24)
				| ((m[j + 1] as u64) << 16)
				| ((m[j + 2] as u64) << 8)
				| (m[j + 3] as u64);

			// Write it to the witness.  Word is a thin wrapper around u64.
			w[self.m[i]] = Word(limb);
		}
	}
}

fn round(builder: &CircuitBuilder, round: usize, state: State, w: &[Wire; 64]) -> State {
	let State([a, b, c, d, e, f, g, h]) = state;

	let big_sigma_e = big_sigma_1(builder, e);
	let ch_efg = ch(builder, e, f, g);
	let t1a = builder.iadd_32(h, big_sigma_e);
	let t1b = builder.iadd_32(t1a, ch_efg);
	let rc = builder.add_constant(Word(K[round] as u64));
	let t1c = builder.iadd_32(t1b, rc);
	let t1 = builder.iadd_32(t1c, w[round]);

	let big_sigma_a = big_sigma_0(builder, a);
	let maj_abc = maj(builder, a, b, c);
	let t2 = builder.iadd_32(big_sigma_a, maj_abc);

	let h = g;
	let g = f;
	let f = e;
	let e = builder.iadd_32(d, t1);
	let d = c;
	let c = b;
	let b = a;
	let a = builder.iadd_32(t1, t2);

	State([a, b, c, d, e, f, g, h])
}

/// Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
///           = g XOR (e AND (f XOR g))
fn ch(builder: &CircuitBuilder, e: Wire, f: Wire, g: Wire) -> Wire {
	builder.bxor(g, builder.band(e, builder.bxor(f, g)))
}

/// Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
///            = (a AND (b XOR c)) XOR (b AND c)
fn maj(builder: &CircuitBuilder, a: Wire, b: Wire, c: Wire) -> Wire {
	builder.bxor(builder.band(a, builder.bxor(b, c)), builder.band(b, c))
}

/// Σ0(a)       = XOR( XOR( ROTR(a,  2), ROTR(a, 13) ), ROTR(a, 22) )
fn big_sigma_0(b: &CircuitBuilder, a: Wire) -> Wire {
	let r1 = b.rotr_32(a, 2);
	let r2 = b.rotr_32(a, 13);
	let r3 = b.rotr_32(a, 22);
	let x1 = b.bxor(r1, r2);
	b.bxor(x1, r3)
}

/// Σ1(e)       = XOR( XOR( ROTR(e,  6), ROTR(e, 11) ), ROTR(e, 25) )
fn big_sigma_1(b: &CircuitBuilder, e: Wire) -> Wire {
	let r1 = b.rotr_32(e, 6);
	let r2 = b.rotr_32(e, 11);
	let r3 = b.rotr_32(e, 25);
	let x1 = b.bxor(r1, r2);
	b.bxor(x1, r3)
}

/// σ0(x)       = XOR( XOR( ROTR(x,  7), ROTR(x, 18) ), SHR(x,  3) )
fn small_sigma_0(b: &CircuitBuilder, x: Wire) -> Wire {
	let r1 = b.rotr_32(x, 7);
	let r2 = b.rotr_32(x, 18);
	let s1 = b.shr_32(x, 3);
	let x1 = b.bxor(r1, r2);
	b.bxor(x1, s1)
}

/// σ1(x)       = XOR( XOR( ROTR(x, 17), ROTR(x, 19) ), SHR(x, 10) )
fn small_sigma_1(b: &CircuitBuilder, x: Wire) -> Wire {
	let r1 = b.rotr_32(x, 17);
	let r2 = b.rotr_32(x, 19);
	let s1 = b.shr_32(x, 10);
	let x1 = b.bxor(r1, r2);
	b.bxor(x1, s1)
}

// ============================================================================
// OPTIMIZED VERSIONS - Direct constraint builder access for performance testing
// ============================================================================

/// Optimized Σ0(a) using single AND constraint instead of 5
/// Uses raw constraint API for 5x fewer constraints
fn big_sigma_0_optimal(b: &CircuitBuilder, a: Wire) -> Wire {
	use crate::compiler::constraint_builder::Shift;
	
	let result = b.add_internal();
	let mask32 = b.add_constant(Word::MASK_32);
	
	b.raw_and_constraint(
		vec![a],           // inputs
		vec![result],      // outputs
		// Operand A: all rotation terms XORed together
		vec![
			(a, Shift::Srl(2)),  (a, Shift::Sll(30)),  // ROTR(a, 2)
			(a, Shift::Srl(13)), (a, Shift::Sll(19)),  // ROTR(a, 13)
			(a, Shift::Srl(22)), (a, Shift::Sll(10)),  // ROTR(a, 22)
		],
		// Operand B: mask
		vec![(mask32, Shift::None)],
		// Operand C: result
		vec![(result, Shift::None)],
		// Witness computation function
		move |inputs| {
			let a_val = inputs[0].0 & 0xFFFFFFFF;
			let r1 = ((a_val >> 2) | (a_val << 30)) & 0xFFFFFFFF;
			let r2 = ((a_val >> 13) | (a_val << 19)) & 0xFFFFFFFF;
			let r3 = ((a_val >> 22) | (a_val << 10)) & 0xFFFFFFFF;
			vec![Word(r1 ^ r2 ^ r3)]
		},
	);
	
	result
}

/// Optimized Σ1(e) using single AND constraint instead of 5
/// Uses raw constraint API for 5x fewer constraints
fn big_sigma_1_optimal(b: &CircuitBuilder, e: Wire) -> Wire {
	use crate::compiler::constraint_builder::Shift;
	
	let result = b.add_internal();
	let mask32 = b.add_constant(Word::MASK_32);
	
	b.raw_and_constraint(
		vec![e],           // inputs
		vec![result],      // outputs
		// Operand A: all rotation terms XORed together
		// Σ1(e) = ROTR(e, 6) ⊕ ROTR(e, 11) ⊕ ROTR(e, 25)
		vec![
			(e, Shift::Srl(6)),  (e, Shift::Sll(26)),  // ROTR(e, 6)
			(e, Shift::Srl(11)), (e, Shift::Sll(21)),  // ROTR(e, 11)
			(e, Shift::Srl(25)), (e, Shift::Sll(7)),   // ROTR(e, 25)
		],
		// Operand B: mask
		vec![(mask32, Shift::None)],
		// Operand C: result
		vec![(result, Shift::None)],
		// Witness computation function
		move |inputs| {
			let e_val = inputs[0].0 & 0xFFFFFFFF;
			let r1 = ((e_val >> 6) | (e_val << 26)) & 0xFFFFFFFF;
			let r2 = ((e_val >> 11) | (e_val << 21)) & 0xFFFFFFFF;
			let r3 = ((e_val >> 25) | (e_val << 7)) & 0xFFFFFFFF;
			vec![Word(r1 ^ r2 ^ r3)]
		},
	);
	
	result
}

/// Optimized σ0(x) using single AND constraint
/// σ0(x) = ROTR(x, 7) ⊕ ROTR(x, 18) ⊕ SHR(x, 3)
fn small_sigma_0_optimal(b: &CircuitBuilder, x: Wire) -> Wire {
	use crate::compiler::constraint_builder::Shift;
	
	let result = b.add_internal();
	let mask32 = b.add_constant(Word::MASK_32);
	
	b.raw_and_constraint(
		vec![x],           // inputs
		vec![result],      // outputs
		// Operand A: all terms XORed together
		vec![
			(x, Shift::Srl(7)),  (x, Shift::Sll(25)),  // ROTR(x, 7)
			(x, Shift::Srl(18)), (x, Shift::Sll(14)),  // ROTR(x, 18)
			(x, Shift::Srl(3)),                         // SHR(x, 3) - just shift, no rotate
		],
		// Operand B: mask
		vec![(mask32, Shift::None)],
		// Operand C: result
		vec![(result, Shift::None)],
		// Witness computation function
		move |inputs| {
			let x_val = inputs[0].0 & 0xFFFFFFFF;
			let r1 = ((x_val >> 7) | (x_val << 25)) & 0xFFFFFFFF;
			let r2 = ((x_val >> 18) | (x_val << 14)) & 0xFFFFFFFF;
			let s1 = (x_val >> 3) & 0xFFFFFFFF;
			vec![Word(r1 ^ r2 ^ s1)]
		},
	);
	
	result
}

/// Optimized σ1(x) using single AND constraint  
/// σ1(x) = ROTR(x, 17) ⊕ ROTR(x, 19) ⊕ SHR(x, 10)
fn small_sigma_1_optimal(b: &CircuitBuilder, x: Wire) -> Wire {
	use crate::compiler::constraint_builder::Shift;
	
	let result = b.add_internal();
	let mask32 = b.add_constant(Word::MASK_32);
	
	b.raw_and_constraint(
		vec![x],           // inputs
		vec![result],      // outputs
		// Operand A: all terms XORed together
		vec![
			(x, Shift::Srl(17)), (x, Shift::Sll(15)),  // ROTR(x, 17)
			(x, Shift::Srl(19)), (x, Shift::Sll(13)),  // ROTR(x, 19)
			(x, Shift::Srl(10)),                        // SHR(x, 10) - just shift
		],
		// Operand B: mask
		vec![(mask32, Shift::None)],
		// Operand C: result
		vec![(result, Shift::None)],
		// Witness computation function
		move |inputs| {
			let x_val = inputs[0].0 & 0xFFFFFFFF;
			let r1 = ((x_val >> 17) | (x_val << 15)) & 0xFFFFFFFF;
			let r2 = ((x_val >> 19) | (x_val << 13)) & 0xFFFFFFFF;
			let s1 = (x_val >> 10) & 0xFFFFFFFF;
			vec![Word(r1 ^ r2 ^ s1)]
		},
	);
	
	result
}

/// Optimized Ch function using single AND constraint
/// Ch(e,f,g) = g ⊕ (e ∧ (f ⊕ g))
fn ch_optimal(b: &CircuitBuilder, e: Wire, f: Wire, g: Wire) -> Wire {
	use crate::compiler::constraint_builder::Shift;
	
	let result = b.add_internal();
	let mask32 = b.add_constant(Word::MASK_32);
	
	// Ch(e,f,g) = g ⊕ (e ∧ (f ⊕ g))
	// We can express this as a single AND constraint:
	// (e ∧ ((f ⊕ g) ∧ mask32)) ⊕ (g ∧ mask32) = result
	// Rearranging: e ∧ (f ⊕ g) = result ⊕ g
	
	b.raw_and_constraint(
		vec![e, f, g],     // inputs
		vec![result],      // outputs
		// Operand A: e
		vec![(e, Shift::None)],
		// Operand B: (f ⊕ g) masked
		vec![(f, Shift::None), (g, Shift::None), (mask32, Shift::None)],
		// Operand C: result ⊕ g
		vec![(result, Shift::None), (g, Shift::None)],
		// Witness computation
		move |inputs| {
			let e_val = inputs[0].0 & 0xFFFFFFFF;
			let f_val = inputs[1].0 & 0xFFFFFFFF;
			let g_val = inputs[2].0 & 0xFFFFFFFF;
			// Ch(e,f,g) = g ⊕ (e ∧ (f ⊕ g))
			let result = g_val ^ (e_val & (f_val ^ g_val));
			vec![Word(result & 0xFFFFFFFF)]
		},
	);
	
	result
}

/// Optimized Maj function using single AND constraint
/// Maj(a,b,c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
///            = (a ∧ (b ⊕ c)) ⊕ (b ∧ c)
fn maj_optimal(b: &CircuitBuilder, a: Wire, b_wire: Wire, c: Wire) -> Wire {
	use crate::compiler::constraint_builder::Shift;
	
	let result = b.add_internal();
	
	// This is trickier - Maj needs 2 AND operations fundamentally
	// But we can combine them into one constraint using the fact that:
	// Maj(a,b,c) = (a ∧ (b ⊕ c)) ⊕ (b ∧ c)
	// We need to be creative here...
	
	// Actually, Maj has a simpler form:
	// Maj(a,b,c) = (a ∧ b) | (b ∧ c) | (a ∧ c)
	//            = b ∧ (a | c) | (a ∧ c)
	//            = Most common bit (majority vote)
	
	// For now, we'll use 2 constraints as it's fundamentally needed
	// TODO: Research if Maj can be done in 1 constraint
	
	let temp = b.add_internal();
	
	// First constraint: temp = a ∧ (b ⊕ c)
	b.raw_and_constraint(
		vec![a, b_wire, c],
		vec![temp],
		vec![(a, Shift::None)],
		vec![(b_wire, Shift::None), (c, Shift::None)],
		vec![(temp, Shift::None)],
		move |inputs| {
			let a_val = inputs[0].0 & 0xFFFFFFFF;
			let b_val = inputs[1].0 & 0xFFFFFFFF;
			let c_val = inputs[2].0 & 0xFFFFFFFF;
			vec![Word(a_val & (b_val ^ c_val) & 0xFFFFFFFF)]
		},
	);
	
	// Second constraint: result = temp ⊕ (b ∧ c)
	b.raw_and_constraint(
		vec![b_wire, c, temp],
		vec![result],
		vec![(b_wire, Shift::None)],
		vec![(c, Shift::None)],
		vec![(result, Shift::None), (temp, Shift::None)],
		move |inputs| {
			let b_val = inputs[0].0 & 0xFFFFFFFF;
			let c_val = inputs[1].0 & 0xFFFFFFFF;
			let temp_val = inputs[2].0 & 0xFFFFFFFF;
			vec![Word((temp_val ^ (b_val & c_val)) & 0xFFFFFFFF)]
		},
	);
	
	result
}

#[cfg(test)]
mod tests {
	use binius_core::word::Word;

	use super::{
		Compress, State, 
		big_sigma_0, big_sigma_1, small_sigma_0, small_sigma_1,
		big_sigma_0_optimal, big_sigma_1_optimal, small_sigma_0_optimal, small_sigma_1_optimal,
		ch, ch_optimal, maj, maj_optimal
	};
	use crate::{
		compiler::{self, Wire},
		constraint_verifier::verify_constraints,
	};

	/// A test circuit that proves a knowledge of preimage for a given state vector S in
	///
	///     compress512(preimage) = S
	///
	/// without revealing the preimage, only S.
	#[test]
	fn proof_preimage() {
		// Use the test-vector for SHA256 single block message: "abc".
		let mut preimage: [u8; 64] = [0; 64];
		preimage[0..3].copy_from_slice(b"abc");
		preimage[3] = 0x80;
		preimage[63] = 0x18;

		#[rustfmt::skip]
		let expected_state: [u32; 8] = [
			0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
			0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
		];

		let circuit = compiler::CircuitBuilder::new();
		let state = State::iv(&circuit);
		let input: [Wire; 16] = std::array::from_fn(|_| circuit.add_witness());
		let output: [Wire; 8] = std::array::from_fn(|_| circuit.add_inout());
		let compress = Compress::new(&circuit, state, input);

		// Mask to only low 32-bit.
		let mask32 = circuit.add_constant(Word::MASK_32);
		for (i, (actual_x, expected_x)) in compress.state_out.0.iter().zip(output).enumerate() {
			circuit.assert_eq(
				format!("preimage_eq[{i}]"),
				circuit.band(*actual_x, mask32),
				expected_x,
			);
		}

		let circuit = circuit.build();
		let cs = circuit.constraint_system();
		let mut w = circuit.new_witness_filler();

		// Populate the input message for the compression function.
		compress.populate_m(&mut w, preimage);

		for (i, &output) in output.iter().enumerate() {
			w[output] = Word(expected_state[i] as u64);
		}
		circuit.populate_wire_witness(&mut w).unwrap();

		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn sha256_chain() {
		// Tests multiple SHA-256 compress512 invocations where the outputs are linked to the inputs
		// of the following compression function.
		//
		// This creates ~100 layers with a lot of computations and a very large number of layers
		// (hundreds of thousands) with a few gates each.
		const N: usize = 1 << 10;
		let circuit = compiler::CircuitBuilder::new();

		println!("{N} sha256 compress512 invocations");

		let mut compress_vec = Vec::with_capacity(N);

		// First, declare the initial state.
		let mut state = State::iv(&circuit);
		for i in 0..N {
			// Create a new subcircuit builder. This is not necessary but can improve readability
			// and diagnostics.
			let sha256_builder = circuit.subcircuit(format!("sha256[{i}]"));

			// Build a new instance of the sha256 verification subcircuit, passing the inputs `m` to
			// it. For the first compression `m` is public but everything else if private.
			let m: [compiler::Wire; 16] = if i == 0 {
				std::array::from_fn(|_| sha256_builder.add_inout())
			} else {
				std::array::from_fn(|_| sha256_builder.add_witness())
			};
			let compress = Compress::new(&sha256_builder, state, m);
			state = compress.state_out.clone();

			compress_vec.push(compress);
		}

		let circuit = circuit.build();
		let cs = circuit.constraint_system();
		let mut w = circuit.new_witness_filler();

		for compress in &compress_vec {
			compress.populate_m(&mut w, [0; 64]);
		}
		circuit.populate_wire_witness(&mut w).unwrap();

		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn sha256_parallel() {
		// Test multiple SHA-256 compressions in parallel (no chaining)
		const N: usize = 1 << 10;
		let circuit = compiler::CircuitBuilder::new();

		println!("{N} sha256 compress512 invocations in parallel");

		let mut compress_vec = Vec::with_capacity(N);

		for i in 0..N {
			// Create a new subcircuit builder
			let sha256_builder = circuit.subcircuit(format!("sha256[{i}]"));

			// Each SHA-256 instance gets its own IV and input (all committed)
			let state = State::iv(&sha256_builder);
			let m: [compiler::Wire; 16] = std::array::from_fn(|_| sha256_builder.add_inout());
			let compress = Compress::new(&sha256_builder, state, m);

			compress_vec.push(compress);
		}

		let circuit = circuit.build();
		let cs = circuit.constraint_system();
		let mut w = circuit.new_witness_filler();

		for compress in &compress_vec {
			compress.populate_m(&mut w, [0; 64]);
		}
		circuit.populate_wire_witness(&mut w).unwrap();

		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	/// Test to measure constraint counts for sigma functions
	/// This demonstrates the optimization opportunity
	#[test]
	fn measure_ch_maj_constraint_counts() {
		// Test Ch function optimization
		{
			let builder = compiler::CircuitBuilder::new();
			let e = builder.add_witness();
			let f = builder.add_witness();
			let g = builder.add_witness();
			
			// Original Ch
			let _result = ch(&builder, e, f, g);
			let circuit = builder.build();
			let original_ch_constraints = circuit.constraint_system().and_constraints.len();
			println!("Original Ch: {} AND constraints", original_ch_constraints);
		}
		
		{
			let builder = compiler::CircuitBuilder::new();
			let e = builder.add_witness();
			let f = builder.add_witness();
			let g = builder.add_witness();
			
			// Optimized Ch
			let _result = ch_optimal(&builder, e, f, g);
			let circuit = builder.build();
			let optimal_ch_constraints = circuit.constraint_system().and_constraints.len();
			println!("Optimized Ch: {} AND constraints", optimal_ch_constraints);
		}
		
		// Test Maj function optimization
		{
			let builder = compiler::CircuitBuilder::new();
			let a = builder.add_witness();
			let b = builder.add_witness();
			let c = builder.add_witness();
			
			// Original Maj
			let _result = maj(&builder, a, b, c);
			let circuit = builder.build();
			let original_maj_constraints = circuit.constraint_system().and_constraints.len();
			println!("Original Maj: {} AND constraints", original_maj_constraints);
		}
		
		{
			let builder = compiler::CircuitBuilder::new();
			let a = builder.add_witness();
			let b = builder.add_witness();
			let c = builder.add_witness();
			
			// Optimized Maj
			let _result = maj_optimal(&builder, a, b, c);
			let circuit = builder.build();
			let optimal_maj_constraints = circuit.constraint_system().and_constraints.len();
			println!("Optimized Maj: {} AND constraints", optimal_maj_constraints);
		}
	}
	
	#[test]
	fn measure_sigma_constraint_counts() {
		println!("\n=== CURRENT IMPLEMENTATION (Non-Optimized) ===\n");
		
		// Test big_sigma_0 CURRENT
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = big_sigma_0(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("big_sigma_0 (CURRENT):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			println!("  Breakdown: 3 rotr_32 + 2 bxor = 5 AND constraints");
			// Actually 5 AND constraints (3 rotr_32 + 2 bxor)
			assert_eq!(cs.and_constraints.len(), 5);
			assert_eq!(cs.mul_constraints.len(), 0);
		}
		
		// Test big_sigma_0 OPTIMIZED
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = big_sigma_0_optimal(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("\nbig_sigma_0 (OPTIMIZED):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			println!("  Reduction: 5 → 1 constraint (80% fewer!)");
			// Should be just 1 AND constraint!
			assert_eq!(cs.and_constraints.len(), 1);
			assert_eq!(cs.mul_constraints.len(), 0);
		}

		// Test big_sigma_1 CURRENT 
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = big_sigma_1(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("big_sigma_1 (CURRENT):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			// Actually 5 AND constraints (3 rotr_32 + 2 bxor)
			assert_eq!(cs.and_constraints.len(), 5);
			assert_eq!(cs.mul_constraints.len(), 0);
		}
		
		// Test big_sigma_1 OPTIMIZED
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = big_sigma_1_optimal(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("\nbig_sigma_1 (OPTIMIZED):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			println!("  Reduction: 5 → 1 constraint (80% fewer!)");
			assert_eq!(cs.and_constraints.len(), 1);
			assert_eq!(cs.mul_constraints.len(), 0);
		}

		// Test small_sigma_0 CURRENT
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = small_sigma_0(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("small_sigma_0 (CURRENT):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			// Actually 5 AND constraints (2 rotr_32 + 1 shr_32 + 2 bxor)
			assert_eq!(cs.and_constraints.len(), 5);
			assert_eq!(cs.mul_constraints.len(), 0);
		}
		
		// Test small_sigma_0 OPTIMIZED
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = small_sigma_0_optimal(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("\nsmall_sigma_0 (OPTIMIZED):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			println!("  Reduction: 5 → 1 constraint (80% fewer!)");
			assert_eq!(cs.and_constraints.len(), 1);
			assert_eq!(cs.mul_constraints.len(), 0);
		}

		// Test small_sigma_1 CURRENT
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = small_sigma_1(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("small_sigma_1 (CURRENT):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			// Actually 5 AND constraints (2 rotr_32 + 1 shr_32 + 2 bxor)
			assert_eq!(cs.and_constraints.len(), 5);
			assert_eq!(cs.mul_constraints.len(), 0);
		}
		
		// Test small_sigma_1 OPTIMIZED
		{
			let builder = compiler::CircuitBuilder::new();
			let input = builder.add_witness();
			let _output = small_sigma_1_optimal(&builder, input);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("\nsmall_sigma_1 (OPTIMIZED):");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			println!("  Reduction: 5 → 1 constraint (80% fewer!)");
			assert_eq!(cs.and_constraints.len(), 1);
			assert_eq!(cs.mul_constraints.len(), 0);
		}

		// Test full compress function
		{
			let builder = compiler::CircuitBuilder::new();
			let state = State::iv(&builder);
			let m: [Wire; 16] = std::array::from_fn(|_| builder.add_witness());
			let _compress = Compress::new(&builder, state, m);
			let circuit = builder.build();
			let cs = circuit.constraint_system();
			
			println!("\n=== FULL SHA-256 COMPRESSION ===");
			println!("Full SHA-256 compress (64 rounds) - CURRENT:");
			println!("  AND constraints: {}", cs.and_constraints.len());
			println!("  MUL constraints: {}", cs.mul_constraints.len());
			println!("  Total gates: {}", circuit.n_gates());
			
			println!("\n=== THEORETICAL OPTIMIZATION POTENTIAL ===");
			println!("IF we could access constraint builder directly:");
			println!("  Current: Each sigma uses 5 AND constraints");
			println!("  Optimal: Each sigma could use 1 AND constraint");
			println!("  How: Merge (rotr⊕rotr⊕rotr) into single operand");
			println!("\nExpected savings:");
			println!("  Per sigma function: 5 → 1 constraints (80% reduction)");
			println!("  Full SHA-256: ~2784 → ~550 constraints (estimated)");
			println!("\nBLOCKER: Gate abstraction forces intermediate witness values");
			println!("BLOCKER: Even XOR creates constraints (should be free)!");
		}
	}
}
