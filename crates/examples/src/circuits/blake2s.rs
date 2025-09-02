//! Blake2s circuit benchmark wrapper

use anyhow::{Result, ensure};
use binius_frontend::{
	circuits::blake2s::Blake2s,
	compiler::{CircuitBuilder, circuit::WitnessFiller},
};
use clap::Args;
use rand::{RngCore, SeedableRng, rngs::StdRng};

use crate::ExampleCircuit;

#[derive(Debug, Clone, Args)]
pub struct Params {
	#[arg(long, default_value_t = 131072)]
	pub max_bytes: usize,
}

#[derive(Debug, Clone, Args)]
pub struct Instance {}

pub struct Blake2sExample {
	blake2s_circuit: Blake2s,
	max_bytes: usize,
}

impl ExampleCircuit for Blake2sExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		ensure!(params.max_bytes > 0, "max_bytes must be positive");

		// Create the Blake2s circuit with the specified max_bytes
		let blake2s_circuit = Blake2s::new_witness(builder, params.max_bytes);

		Ok(Self {
			blake2s_circuit,
			max_bytes: params.max_bytes,
		})
	}

	fn populate_witness(&self, _instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Generate deterministic random message using the full capacity
		let mut rng = StdRng::seed_from_u64(42);
		let mut message_bytes = vec![0u8; self.max_bytes];
		rng.fill_bytes(&mut message_bytes);

		// Compute the expected digest using blake2 crate
		use blake2::{Blake2s256, Digest};
		let mut hasher = Blake2s256::new();
		hasher.update(&message_bytes);
		let digest = hasher.finalize();
		let digest_bytes: [u8; 32] = digest.into();

		// Populate the witness
		self.blake2s_circuit.populate_message(w, &message_bytes);
		self.blake2s_circuit.populate_digest(w, &digest_bytes);

		Ok(())
	}
}
