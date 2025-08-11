use binius_core::word::Word;

use crate::{
	circuits::keccak::reference::{R, RC, idx},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};

pub const PADDING_BYTE: u8 = 0x01;

#[derive(Clone, Copy)]
pub struct State {
	pub words: [Wire; 25],
}

/// Keccak f\[1600\] permutation circuit.
pub struct Permutation {
	pub input_state: State,
	pub output_state: State,
}

impl Permutation {
	/// Create a new permutation circuit.
	///
	/// ## Arguments
	///
	/// * `b` - The circuit builder to use.
	pub fn new(b: &CircuitBuilder, input_state: State) -> Self {
		let mut output_state = input_state;
		Self::keccak_f1600(b, &mut output_state.words);

		Self {
			input_state,
			output_state,
		}
	}

	/// Populate the state with the given witness.
	///
	/// ## Arguments
	///
	/// * `w` - The witness to populate the state with.
	/// * `state` - The state to populate the witness with.
	pub fn populate_state(&self, w: &mut WitnessFiller, state: [u64; 25]) {
		for i in 0..25 {
			w[self.input_state.words[i]] = Word(state[i]);
		}
	}

	/// Perform the Keccak f\[1600\] permutation.
	///
	/// ## Arguments
	///
	/// * `b` - The circuit builder to use.
	/// * `state` - The state to perform the permutation on.
	pub fn keccak_f1600(b: &CircuitBuilder, state: &mut [Wire; 25]) {
		for round in 0..24 {
			Self::keccak_permutation_round(b, state, round);
		}
	}

	fn keccak_permutation_round(b: &CircuitBuilder, state: &mut [Wire; 25], round: usize) {
		Self::theta(b, state);
		Self::rho_pi(b, state);
		Self::chi(b, state);
		Self::iota(b, state, round);
	}

	fn theta(b: &CircuitBuilder, state: &mut [Wire; 25]) {
		let c0 = b.bxor(
			b.bxor(
				b.bxor(b.bxor(state[idx(0, 0)], state[idx(0, 1)]), state[idx(0, 2)]),
				state[idx(0, 3)],
			),
			state[idx(0, 4)],
		);
		let c1 = b.bxor(
			b.bxor(
				b.bxor(b.bxor(state[idx(1, 0)], state[idx(1, 1)]), state[idx(1, 2)]),
				state[idx(1, 3)],
			),
			state[idx(1, 4)],
		);
		let c2 = b.bxor(
			b.bxor(
				b.bxor(b.bxor(state[idx(2, 0)], state[idx(2, 1)]), state[idx(2, 2)]),
				state[idx(2, 3)],
			),
			state[idx(2, 4)],
		);
		let c3 = b.bxor(
			b.bxor(
				b.bxor(b.bxor(state[idx(3, 0)], state[idx(3, 1)]), state[idx(3, 2)]),
				state[idx(3, 3)],
			),
			state[idx(3, 4)],
		);
		let c4 = b.bxor(
			b.bxor(
				b.bxor(b.bxor(state[idx(4, 0)], state[idx(4, 1)]), state[idx(4, 2)]),
				state[idx(4, 3)],
			),
			state[idx(4, 4)],
		);

		// D[x] = C[x-1] ^ rotl1(C[x+1])
		let d0 = b.bxor(c4, rotate_left(b, c1, 1));
		let d1 = b.bxor(c0, rotate_left(b, c2, 1));
		let d2 = b.bxor(c1, rotate_left(b, c3, 1));
		let d3 = b.bxor(c2, rotate_left(b, c4, 1));
		let d4 = b.bxor(c3, rotate_left(b, c0, 1));

		// A'[x,y] = A[x,y] ^ D[x]
		for y in 0..5 {
			state[idx(0, y)] = b.bxor(state[idx(0, y)], d0);
			state[idx(1, y)] = b.bxor(state[idx(1, y)], d1);
			state[idx(2, y)] = b.bxor(state[idx(2, y)], d2);
			state[idx(3, y)] = b.bxor(state[idx(3, y)], d3);
			state[idx(4, y)] = b.bxor(state[idx(4, y)], d4);
		}
	}

	fn chi(b: &CircuitBuilder, state: &mut [Wire; 25]) {
		for y in 0..5 {
			let a0 = state[idx(0, y)];
			let a1 = state[idx(1, y)];
			let a2 = state[idx(2, y)];
			let a3 = state[idx(3, y)];
			let a4 = state[idx(4, y)];

			state[idx(0, y)] = b.bxor(a0, b.band(b.bnot(a1), a2));
			state[idx(1, y)] = b.bxor(a1, b.band(b.bnot(a2), a3));
			state[idx(2, y)] = b.bxor(a2, b.band(b.bnot(a3), a4));
			state[idx(3, y)] = b.bxor(a3, b.band(b.bnot(a4), a0));
			state[idx(4, y)] = b.bxor(a4, b.band(b.bnot(a0), a1));
		}
	}

	fn rho_pi(b: &CircuitBuilder, state: &mut [Wire; 25]) {
		let mut temp = [state[0]; 25];
		for y in 0..5 {
			for x in 0..5 {
				temp[idx(y, (2 * x + 3 * y) % 5)] = rotate_left(b, state[idx(x, y)], R[idx(x, y)]);
			}
		}
		*state = temp;
	}

	fn iota(b: &CircuitBuilder, state: &mut [Wire; 25], round: usize) {
		let rc_wire = b.add_constant(Word(RC[round]));
		state[0] = b.bxor(state[0], rc_wire);
	}
}

pub fn rotate_left(b: &CircuitBuilder, x: Wire, n: u32) -> Wire {
	let k = n % 64;
	if k == 0 {
		x
	} else {
		b.bxor(b.shl(x, k), b.shr(x, 64 - k))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		circuits::keccak::reference::{
			chi_reference, iota_reference, keccak_f1600_reference,
			keccak_permutation_round_reference, rho_pi_reference, theta_reference,
		},
		compiler::CircuitBuilder,
		constraint_verifier::verify_constraints,
	};
	use binius_core::word::Word;
	use rand::{Rng, SeedableRng, rngs::StdRng};

	#[test]
	fn test_keccak_permutation() {
		let mut rng = StdRng::seed_from_u64(0);

		let builder = CircuitBuilder::new();

		let input_words = State {
			words: std::array::from_fn(|_| builder.add_inout()),
		};

		let permutation = Permutation::new(&builder, input_words);

		let circuit = builder.build();

		let mut w = circuit.new_witness_filler();

		let initial_state = rng.random::<[u64; 25]>();
		permutation.populate_state(&mut w, initial_state);

		circuit.populate_wire_witness(&mut w).unwrap();

		let mut expected_output = initial_state;
		keccak_f1600_reference(&mut expected_output);

		for i in 0..25 {
			assert_eq!(w[permutation.output_state.words[i]], Word(expected_output[i]));
		}

		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	fn validate_circuit_component(
		circuit_fn: impl FnOnce(&CircuitBuilder, &mut [Wire; 25]),
		reference_fn: impl FnOnce(&mut [u64; 25]),
		input_state: [u64; 25],
	) {
		let builder = CircuitBuilder::new();

		let input_wires: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());

		let mut state_wires = input_wires;
		circuit_fn(&builder, &mut state_wires);
		let circuit = builder.build();

		let mut expected_output = input_state;
		reference_fn(&mut expected_output);

		let mut w = circuit.new_witness_filler();
		for i in 0..25 {
			w[input_wires[i]] = Word(input_state[i]);
		}
		circuit.populate_wire_witness(&mut w).unwrap();

		for i in 0..25 {
			assert_eq!(
				w[state_wires[i]],
				Word(expected_output[i]),
				"Output mismatch at index {}: circuit={:?}, expected={:?}",
				i,
				w[state_wires[i]],
				Word(expected_output[i])
			);
		}

		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}

	#[test]
	fn test_keccak_f1600() {
		let mut rng = StdRng::seed_from_u64(0);
		let input_state = rng.random::<[u64; 25]>();

		validate_circuit_component(Permutation::keccak_f1600, keccak_f1600_reference, input_state);
	}

	#[test]
	fn test_keccak_permutation_round() {
		let mut rng = StdRng::seed_from_u64(0);
		let input_state = rng.random::<[u64; 25]>();

		validate_circuit_component(
			|b, state| Permutation::keccak_permutation_round(b, state, 0),
			|state| keccak_permutation_round_reference(state, 0),
			input_state,
		);
	}

	#[test]
	fn test_theta() {
		let mut rng = StdRng::seed_from_u64(0);
		let input_state = rng.random::<[u64; 25]>();

		validate_circuit_component(
			Permutation::theta,
			|state| theta_reference(state, 0),
			input_state,
		);
	}

	#[test]
	fn test_rho_pi() {
		let mut rng = StdRng::seed_from_u64(0);
		let input_state = rng.random::<[u64; 25]>();

		validate_circuit_component(
			Permutation::rho_pi,
			|state| rho_pi_reference(state, 0),
			input_state,
		);
	}

	#[test]
	fn test_chi() {
		let mut rng = StdRng::seed_from_u64(0);
		let input_state = rng.random::<[u64; 25]>();

		validate_circuit_component(Permutation::chi, chi_reference, input_state);
	}

	#[test]
	fn test_iota() {
		let mut rng = StdRng::seed_from_u64(0);
		let input_state = rng.random::<[u64; 25]>();

		validate_circuit_component(
			|b, state| Permutation::iota(b, state, 0),
			|state| iota_reference(state, 0),
			input_state,
		);
	}
}
