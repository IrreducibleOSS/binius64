use std::array;

use anyhow::Result;
use binius_core::Word;
use binius_frontend::{
	circuits::hash_based_sig::{
		winternitz_ots::WinternitzSpec,
		witness_utils::{ValidatorSignatureData, XmssHasherData, populate_xmss_hashers},
		xmss::XmssSignature,
		xmss_aggregate::{XmssMultisigHashers, circuit_xmss_multisig},
	},
	compiler::{CircuitBuilder, Wire, circuit::WitnessFiller},
	util::pack_bytes_into_wires_le,
};
use clap::Args;
use rand::{RngCore, SeedableRng, rngs::StdRng};

use crate::ExampleCircuit;

/// Hash-based multi-signature verification example circuit
pub struct HashBasedSigExample {
	spec: WinternitzSpec,
	tree_height: usize,
	num_validators: usize,
	param: Vec<Wire>,
	message: Vec<Wire>,
	epoch: Wire,
	validator_roots: Vec<[Wire; 4]>,
	validator_signatures: Vec<XmssSignature>,
	hashers: XmssMultisigHashers,
}

#[derive(Args, Debug, Clone)]
pub struct Params {
	/// Number of validators in the multi-signature
	#[arg(short = 'n', long, default_value_t = 3)]
	pub num_validators: usize,

	/// Height of the Merkle tree (2^height slots)
	#[arg(short = 't', long, default_value_t = 3)]
	pub tree_height: usize,

	/// Winternitz spec: 1 or 2
	#[arg(short = 's', long, default_value_t = 1)]
	pub spec: u8,
}

#[derive(Args, Debug, Clone)]
pub struct Instance {}

impl ExampleCircuit for HashBasedSigExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let spec = match params.spec {
			1 => WinternitzSpec::spec_1(),
			2 => WinternitzSpec::spec_2(),
			_ => anyhow::bail!("Invalid spec: must be 1 or 2"),
		};

		let tree_height = params.tree_height;
		if tree_height >= 10 {
			anyhow::bail!("tree_height {} exceeds the maximum supported height of 10", tree_height);
		}
		let num_validators = params.num_validators;

		let param_wire_count = spec.domain_param_len.div_ceil(8);
		let param: Vec<Wire> = (0..param_wire_count).map(|_| builder.add_inout()).collect();
		let message: Vec<Wire> = (0..4).map(|_| builder.add_inout()).collect();
		let epoch = builder.add_inout();

		let validator_roots: Vec<[Wire; 4]> = (0..num_validators)
			.map(|_| array::from_fn(|_| builder.add_inout()))
			.collect();

		let validator_signatures: Vec<XmssSignature> = (0..num_validators)
			.map(|_| XmssSignature {
				nonce: (0..3).map(|_| builder.add_witness()).collect(),
				epoch, // All validators use the same epoch wire
				signature_hashes: (0..spec.dimension())
					.map(|_| array::from_fn(|_| builder.add_witness()))
					.collect(),
				public_key_hashes: (0..spec.dimension())
					.map(|_| array::from_fn(|_| builder.add_witness()))
					.collect(),
				auth_path: (0..tree_height)
					.map(|_| array::from_fn(|_| builder.add_witness()))
					.collect(),
			})
			.collect();

		let hashers = circuit_xmss_multisig(
			builder,
			&spec,
			&param,
			&message,
			epoch,
			&validator_roots,
			&validator_signatures,
		);

		Ok(Self {
			spec,
			tree_height,
			num_validators,
			param,
			message,
			epoch,
			validator_roots,
			validator_signatures,
			hashers,
		})
	}

	fn populate_witness(&self, _instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		let mut rng = StdRng::seed_from_u64(42); // Fixed seed for benchmarking consistency

		let mut param_bytes = vec![0u8; self.spec.domain_param_len];
		rng.fill_bytes(&mut param_bytes);

		// Fixed 32-byte message
		let mut message_bytes = [0u8; 32];
		rng.fill_bytes(&mut message_bytes);

		// Safe because tree_height is validated to be < 10 in build()
		let epoch = rng.next_u32() % (1u32 << self.tree_height);

		// Pack param_bytes (pad to match wire count)
		let mut padded_param = vec![0u8; self.param.len() * 8];
		padded_param[..param_bytes.len()].copy_from_slice(&param_bytes);
		pack_bytes_into_wires_le(w, &self.param, &padded_param);
		pack_bytes_into_wires_le(w, &self.message, &message_bytes);
		w[self.epoch] = Word::from_u64(epoch as u64);

		// Generate a signature for each validator
		for val_idx in 0..self.num_validators {
			let validator_data = ValidatorSignatureData::generate(
				&mut rng,
				&param_bytes,
				&message_bytes,
				epoch,
				&self.spec,
				self.tree_height,
			);

			pack_bytes_into_wires_le(w, &self.validator_roots[val_idx], &validator_data.root);

			let mut nonce_padded = [0u8; 24];
			nonce_padded[..23].copy_from_slice(&validator_data.nonce);
			pack_bytes_into_wires_le(w, &self.validator_signatures[val_idx].nonce, &nonce_padded);

			for (i, sig_hash) in validator_data.signature_hashes.iter().enumerate() {
				pack_bytes_into_wires_le(
					w,
					&self.validator_signatures[val_idx].signature_hashes[i],
					sig_hash,
				);
			}

			for (i, pk_hash) in validator_data.public_key_hashes.iter().enumerate() {
				pack_bytes_into_wires_le(
					w,
					&self.validator_signatures[val_idx].public_key_hashes[i],
					pk_hash,
				);
			}

			for (i, auth_node) in validator_data.auth_path.iter().enumerate() {
				pack_bytes_into_wires_le(
					w,
					&self.validator_signatures[val_idx].auth_path[i],
					auth_node,
				);
			}

			let hasher_data = XmssHasherData {
				param_bytes: param_bytes.clone(),
				message_bytes,
				nonce_bytes: validator_data.nonce.to_vec(),
				epoch: epoch as u64,
				coords: validator_data.coords,
				sig_hashes: validator_data.signature_hashes,
				pk_hashes: validator_data.public_key_hashes,
				auth_path: validator_data.auth_path,
			};

			populate_xmss_hashers(
				w,
				&self.hashers.validator_hashers[val_idx],
				&self.spec,
				&hasher_data,
			);
		}

		Ok(())
	}
}
