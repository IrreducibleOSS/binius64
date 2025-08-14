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
		// Create initial state as witness wires
		let initial_state: [Wire; 25] = std::array::from_fn(|_| builder.add_inout());

		// Chain n permutations
		let mut state = initial_state;
		for _ in 0..params.n_permutations {
			Permutation::keccak_f1600(builder, &mut state);
		}

		// Store final state
		let final_state = state;

		Ok(Self {
			n_permutations: params.n_permutations,
			initial_state,
			final_state,
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

		Ok(())
	}
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<KeccakExample>::new("keccak")
		.about("Keccak-f[1600] permutation example - chains multiple permutations together")
		.run()
}
