use anyhow::{Result, ensure};
use binius_frontend::{
	circuits::semaphore_ecdsa::{IdentityECDSA, MerkleTree, SemaphoreProofECDSA},
	compiler::{CircuitBuilder, circuit::WitnessFiller},
};
use clap::Args;

use crate::ExampleCircuit;

/// Semaphore anonymous group membership proof with ECDSA key derivation
pub struct SemaphoreExample {
	circuit: SemaphoreProofECDSA,
	tree_height: usize,
	message_len_bytes: usize,
	scope_len_bytes: usize,
}

#[derive(Args, Debug, Clone)]
pub struct Params {
	/// Height of the Merkle tree (determines max group size = 2^height)
	#[arg(long, default_value_t = 2)]
	pub tree_height: usize,

	/// Maximum message length in bytes
	#[arg(long, default_value_t = 32)]
	pub message_len_bytes: usize,

	/// Maximum scope length in bytes  
	#[arg(long, default_value_t = 24)]
	pub scope_len_bytes: usize,
}

#[derive(Args, Debug, Clone)]
pub struct Instance {
	/// Number of group members to create
	#[arg(long, default_value_t = 4)]
	pub group_size: usize,

	/// Index of the member generating the proof (0-based)
	#[arg(long, default_value_t = 1)]
	pub prover_index: usize,

	/// Message to include in the proof
	#[arg(long, default_value = "I vote YES on proposal #42")]
	pub message: String,

	/// Scope for this signal (prevents double-signaling within scope)
	#[arg(long, default_value = "dao_vote_2024_q1")]
	pub scope: String,
}

impl ExampleCircuit for SemaphoreExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		ensure!(params.tree_height > 0, "Tree height must be > 0");
		ensure!(params.message_len_bytes > 0, "Message length must be > 0");
		ensure!(params.scope_len_bytes > 0, "Scope length must be > 0");

		let circuit = SemaphoreProofECDSA::new(
			builder,
			params.tree_height,
			params.message_len_bytes,
			params.scope_len_bytes,
		);

		Ok(Self {
			circuit,
			tree_height: params.tree_height,
			message_len_bytes: params.message_len_bytes,
			scope_len_bytes: params.scope_len_bytes,
		})
	}

	fn populate_witness(&self, instance: Instance, witness: &mut WitnessFiller) -> Result<()> {
		// Validate inputs
		ensure!(instance.group_size > 0, "Group size must be > 0");
		ensure!(instance.prover_index < instance.group_size, "Prover index must be < group size");
		ensure!(instance.group_size <= (1 << self.tree_height), "Group size exceeds tree capacity");
		ensure!(instance.message.len() <= self.message_len_bytes, "Message too long");
		ensure!(instance.scope.len() <= self.scope_len_bytes, "Scope too long");

		// Create ECDSA identities
		let mut identities = Vec::new();
		for i in 0..instance.group_size {
			let secret_scalar = [((i + 42) as u8); 32];
			identities.push(IdentityECDSA::new(secret_scalar));
		}

		// Build Merkle tree
		let mut tree = MerkleTree::new(self.tree_height);
		for identity in &identities {
			tree.add_leaf(identity.commitment());
		}

		// Get proof for the prover
		let prover_identity = &identities[instance.prover_index];
		let merkle_proof = tree.proof(instance.prover_index);

		// Populate witness
		self.circuit.populate_witness(
			witness,
			prover_identity,
			&merkle_proof,
			instance.message.as_bytes(),
			instance.scope.as_bytes(),
		);

		Ok(())
	}
}
