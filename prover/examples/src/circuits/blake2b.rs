// Copyright 2025 Irreducible Inc.

use anyhow::{Result, ensure};
use binius_circuits::blake2b::{Blake2bCircuit, blake2b};
use binius_frontend::{CircuitBuilder, WitnessFiller};
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

		let blake2b_circuit = Blake2bCircuit::new_with_length(builder, params.max_msg_len_bytes);

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

		// Compute the expected digest
		let expected_digest_vec = blake2b(&message_bytes, 64);
		let mut expected_digest = [0u8; 64];
		expected_digest.copy_from_slice(&expected_digest_vec);

		// Populate the message and digest in the witness
		self.blake2b_circuit.populate_message(w, &message_bytes);
		self.blake2b_circuit.populate_digest(w, &expected_digest);

		Ok(())
	}
}
