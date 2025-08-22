use anyhow::Result;
use binius_core::word::Word;
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::{
	circuits::keccak::permutation::Permutation,
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
};
use clap::Args;
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Example circuit that chains multiple Keccak-f[1600] permutations
struct KeccakExample {
	#[allow(dead_code)]
	n_permutations: usize,
	initial_state: [Wire; 25],
	#[allow(dead_code)]
	final_state: [Wire; 25],
}

#[derive(Args, Debug)]
struct Params {
	/// Number of Keccak-f[1600] permutations to chain together
	#[arg(short = 'n', long, default_value_t = 10)]
	n_permutations: usize,
}

#[derive(Args, Debug)]
struct Instance {
	// No instance-specific data needed - using fixed random seed
}

impl ExampleCircuit for KeccakExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// Create:
		// 1. initial state as inout wires.
		// 2. expected final state as inout wires.
		let initial_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());
		let expected_final_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());

		// Chain n permutations starting from initial state
		let mut computed_state = initial_state;
		for _ in 0..params.n_permutations {
			Permutation::keccak_f1600(builder, &mut computed_state);
		}

		// Constrain computed final state to equal expected final state
		builder.assert_eq_v("final_state", computed_state, expected_final_state);

		Ok(Self {
			n_permutations: params.n_permutations,
			initial_state,
			final_state: expected_final_state,
		})
	}

	fn populate_witness(&self, _instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Generate random initial state with fixed seed for reproducibility
		let mut rng = StdRng::seed_from_u64(0);
		let initial_state: [u64; 25] = rng.random();

		// Populate initial state witness
		for i in 0..25 {
			w[self.initial_state[i]] = Word(initial_state[i]);
		}

		// Compute expected final state by running the permutation outside the circuit
		let mut expected_final_state = initial_state;
		for _ in 0..self.n_permutations {
			binius_frontend::circuits::keccak::reference::keccak_f1600_reference(
				&mut expected_final_state,
			);
		}

		// Populate expected final state witness
		for i in 0..25 {
			w[self.final_state[i]] = Word(expected_final_state[i]);
		}

		Ok(())
	}
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<KeccakExample>::new("keccak")
		.about("Keccak-f[1600] permutation example - chains multiple permutations together")
		.run()
}
