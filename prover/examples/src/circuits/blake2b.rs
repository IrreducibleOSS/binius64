// Copyright 2025 Irreducible Inc.

use anyhow::{Result, ensure};
use binius_frontend::{
	circuits::blake2b::{Blake2bCircuit, circuit::MAX_BLOCKS},
	compiler::{CircuitBuilder, circuit::WitnessFiller},
};
use clap::Args;
use rand::prelude::*;

use crate::ExampleCircuit;

pub struct Blake2bExample {
	blake2b_circuit: Blake2bCircuit,
	max_msg_len_bytes: usize,
}

#[derive(Args, Debug, Clone)]
pub struct Params {
	/// Maximum message length in bytes that the circuit can handle.
	#[arg(long, default_value_t = 128)]
	pub max_msg_len_bytes: usize,
}

#[derive(Args, Debug, Clone)]
pub struct Instance {}

impl ExampleCircuit for Blake2bExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		// Blake2b processes messages in 128-byte blocks
		ensure!(params.max_msg_len_bytes > 0, "Message length must be positive");
		ensure!(
			params.max_msg_len_bytes <= MAX_BLOCKS * 128,
			"Message length exceeds maximum supported size"
		);

		let blake2b_circuit = Blake2bCircuit::new(builder);

		Ok(Self {
			blake2b_circuit,
			max_msg_len_bytes: params.max_msg_len_bytes,
		})
	}

	fn populate_witness(&self, _instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Generate random message with fixed seed for reproducibility
		let mut rng = StdRng::seed_from_u64(42);

		let mut message_bytes = vec![0u8; self.max_msg_len_bytes];
		rng.fill_bytes(&mut message_bytes);

		// Populate the message and length in the witness
		self.blake2b_circuit.populate_message(w, &message_bytes);
		self.blake2b_circuit.populate_length(w, &message_bytes);

		// The circuit will compute the digest internally
		// We don't need to populate the digest as it's computed by the circuit

		Ok(())
	}
}
