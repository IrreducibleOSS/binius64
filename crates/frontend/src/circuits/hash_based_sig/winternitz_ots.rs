use rand::{RngCore, rngs::StdRng};

use super::{
	chain_verification::circuit_chain,
	codeword::{codeword, extract_coordinates},
	hashing::{build_message_hash, circuit_message_hash, hash_message},
};
use crate::{
	circuits::keccak::Keccak,
	compiler::{CircuitBuilder, Wire},
};

/// Result of Winternitz OTS verification containing hashers that need to be populated.
pub struct WinternitzOtsHashers {
	/// The Keccak hasher for the message tweak operation.
	/// This hasher computes hash(domain_param || TWEAK_MESSAGE || nonce || message).
	/// Must be populated with the tweaked message and its digest.
	pub message_hasher: Keccak,

	/// Vector of Keccak hashers for all chain verification steps.
	/// Each chain has (chain_len) hashers, one for each step in the hash chain.
	/// These compute hash(domain_param || TWEAK_CHAIN || current_hash || chain_index || position).
	/// Must be populated with the chain tweak messages and their corresponding digests.
	pub chain_hashers: Vec<Keccak>,
}

/// Verifies a Winternitz One-Time Signature.
///
/// This circuit implements verification for the Winternitz OTS scheme, which combines:
/// 1. Message hashing with tweaking
/// 2. Codeword extraction from the hash
/// 3. Hash chain verification for each coordinate
///
/// # Arguments
///
/// * `builder` - Circuit builder for constructing constraints
/// * `domain_param` - Cryptographic domain parameter (32 bytes as 4x64-bit LE wires)
/// * `message` - Message to verify (32 bytes as 4x64-bit LE wires)
/// * `nonce` - Random nonce used in signing (23 bytes)
/// * `signature_hashes` - Signature hash values (one per chain)
/// * `public_key_hashes` - Public key end hashes (one per chain)
/// * `spec` - Winternitz specification parameters
///
/// # Returns
///
/// A `WinternitzOtsResult` containing the hashers that need to be populated
pub fn circuit_winternitz_ots(
	builder: &CircuitBuilder,
	domain_param: &[Wire],
	message: &[Wire],
	nonce: &[Wire],
	signature_hashes: &[[Wire; 4]],
	public_key_hashes: &[[Wire; 4]],
	spec: &WinternitzSpec,
) -> WinternitzOtsHashers {
	assert!(
		spec.domain_param_len <= domain_param.len() * 8,
		"domain_param wires must have capacity for {} bytes, but only has capacity for {} bytes",
		spec.domain_param_len,
		domain_param.len() * 8
	);
	assert_eq!(message.len(), 4, "message must be 32 bytes as 4 wires");

	// Step 1: Hash the message with tweaking (domain_param || TWEAK_MESSAGE || nonce || message)
	let message_hash_output: [Wire; 4] = std::array::from_fn(|_| builder.add_witness());
	// Note: nonce is 23 bytes, but packed into 3 wires (24 bytes)
	let nonce_len = 23; // Actual nonce length in bytes
	let message_len = 32; // Message is 32 bytes (4 wires * 8 bytes)
	let message_hasher = circuit_message_hash(
		builder,
		domain_param.to_vec(),
		spec.domain_param_len,
		nonce.to_vec(),
		nonce_len,
		message.to_vec(),
		message_len,
		message_hash_output,
	);

	// Step 2: Extract codeword from message hash
	// Only use the first spec.message_hash_len bytes
	let message_hash_bytes = spec.message_hash_len;
	let message_hash_wires_needed = message_hash_bytes.div_ceil(8);
	let message_hash_for_codeword = &message_hash_output[..message_hash_wires_needed];

	let coordinates = codeword(
		builder,
		spec.dimension(),
		spec.coordinate_resolution_bits,
		spec.target_sum,
		message_hash_for_codeword,
	);

	assert_eq!(coordinates.len(), spec.dimension(), "Codeword dimension mismatch");
	assert_eq!(signature_hashes.len(), spec.dimension(), "Signature hashes count mismatch");
	assert_eq!(public_key_hashes.len(), spec.dimension(), "Public key hashes count mismatch");

	// Step 3: Verify hash chains for each coordinate
	let mut all_chain_hashers = Vec::new();
	let max_chain_len = spec.chain_len();

	for chain_index in 0..spec.dimension() {
		let chain_index_wire = builder.add_constant_64(chain_index as u64);

		// For each chain, verify that hashing from signature_hash for `coordinate` steps
		// produces the public_key_hash
		let chain_hashers = circuit_chain(
			builder,
			domain_param,
			spec.domain_param_len,
			chain_index_wire,
			signature_hashes[chain_index],
			coordinates[chain_index],
			max_chain_len as u64,
			public_key_hashes[chain_index],
		);

		all_chain_hashers.extend(chain_hashers);
	}

	WinternitzOtsHashers {
		message_hasher,
		chain_hashers: all_chain_hashers,
	}
}

/// Specification for Winternitz OTS parameters
///
/// # Constraints
/// - `message_hash_len` must be <= 32 bytes (the output size of Keccak-256)
/// - `coordinate_resolution_bits` must divide evenly into `message_hash_len * 8`
pub struct WinternitzSpec {
	/// Number of bytes from message hash to use (must be <= 32)
	pub message_hash_len: usize,
	/// Number of bits per coordinate in the codeword
	pub coordinate_resolution_bits: usize,
	/// Expected sum of all coordinates
	pub target_sum: u64,
	/// Size of the domain parameter in bytes
	pub domain_param_len: usize,
}

impl WinternitzSpec {
	/// Creates a new WinternitzSpec with validation
	///
	/// # Panics
	/// - If `message_hash_len` > 32 (exceeds Keccak-256 output size)
	/// - If `coordinate_resolution_bits` doesn't divide evenly into `message_hash_len * 8`
	pub fn new(
		message_hash_len: usize,
		coordinate_resolution_bits: usize,
		target_sum: u64,
		domain_param_len: usize,
	) -> Self {
		assert!(
			message_hash_len <= 32,
			"message_hash_len {} exceeds maximum of 32 bytes (Keccak-256 output size)",
			message_hash_len
		);
		assert!(
			(message_hash_len * 8) % coordinate_resolution_bits == 0,
			"coordinate_resolution_bits {} must divide evenly into message_hash_len * 8 = {}",
			coordinate_resolution_bits,
			message_hash_len * 8
		);

		Self {
			message_hash_len,
			coordinate_resolution_bits,
			target_sum,
			domain_param_len,
		}
	}

	/// Returns the number of coordinates/chains
	/// Computed as: message_hash_len * 8 / coordinate_resolution_bits
	pub fn dimension(&self) -> usize {
		self.message_hash_len * 8 / self.coordinate_resolution_bits
	}

	/// Returns the chain length (2^coordinate_resolution_bits)
	pub fn chain_len(&self) -> usize {
		1 << self.coordinate_resolution_bits
	}

	/// Create a spec matching SPEC_1 from leansig-xmss
	pub fn spec_1() -> Self {
		Self::new(18, 2, 119, 18)
	}

	/// Create a spec matching SPEC_2 from leansig-xmss
	pub fn spec_2() -> Self {
		Self::new(18, 4, 297, 18)
	}
}

/// Result of successfully grinding a nonce that produces a valid target sum.
///
/// Contains all the necessary components for Winternitz OTS signature generation
/// after finding a nonce that makes the codeword coordinates sum to the target value.
pub struct GrindResult {
	/// The complete tweaked message: param || 0x02 || nonce || message
	pub tweaked_message: Vec<u8>,
	/// The extracted codeword coordinates from the message hash
	pub coords: Vec<u8>,
	/// The nonce value that achieved the target sum
	pub nonce: Vec<u8>,
}

/// Grind for a nonce that produces codeword coordinates summing to the target value.
///
/// This function repeatedly generates random nonces and computes the tweaked message hash
/// until it finds one where the extracted codeword coordinates sum to the target value
/// specified in the Winternitz specification.
///
/// # Arguments
///
/// * `spec` - The Winternitz OTS specification containing dimension, resolution, and target sum
/// * `rng` - Random number generator for generating nonce candidates
/// * `param` - The cryptographic parameter
/// * `message` - The message to be signed
///
/// # Returns
///
/// * `Some(GrindResult)` - Contains the successful nonce, tweaked message, and coordinates
/// * `None` - Failed to find a valid nonce within 1000 attempts.
pub fn grind_nonce(
	spec: &WinternitzSpec,
	rng: &mut StdRng,
	param: &[u8],
	message: &[u8],
) -> Option<GrindResult> {
	let mut nonce = vec![0u8; 23];
	for _ in 0..1000 {
		rng.fill_bytes(&mut nonce);
		let tweaked_message_hash = hash_message(param, &nonce, message);

		let coords = extract_coordinates(
			&tweaked_message_hash[..spec.message_hash_len],
			spec.dimension(),
			spec.coordinate_resolution_bits,
		);

		let coord_sum: usize = coords.iter().map(|&c| c as usize).sum();
		if coord_sum == spec.target_sum as usize {
			let tweaked_message = build_message_hash(param, &nonce, message);
			return Some(GrindResult {
				tweaked_message,
				coords,
				nonce,
			});
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use rand::{RngCore, SeedableRng, rngs::StdRng};

	use super::{
		super::hashing::{build_chain_hash, hash_chain_keccak},
		*,
	};
	use crate::{constraint_verifier::verify_constraints, util::pack_bytes_into_wires_le};

	#[test]
	fn test_circuit_winternitz_ots() {
		let spec = WinternitzSpec::spec_1();
		let builder = CircuitBuilder::new();

		// Create input wires
		// domain_param is 18 bytes, which needs 3 wires (3*8 = 24 bytes, with padding)
		let domain_param: Vec<Wire> = (0..3).map(|_| builder.add_inout()).collect();
		let message: Vec<Wire> = (0..4).map(|_| builder.add_inout()).collect();
		let nonce: Vec<Wire> = (0..3).map(|_| builder.add_inout()).collect(); // 23 bytes = 3*8 - 1

		let signature_hashes: Vec<[Wire; 4]> = (0..spec.dimension())
			.map(|_| std::array::from_fn(|_| builder.add_inout()))
			.collect();

		let public_key_hashes: Vec<[Wire; 4]> = (0..spec.dimension())
			.map(|_| std::array::from_fn(|_| builder.add_inout()))
			.collect();

		// Create the verification circuit
		let result = circuit_winternitz_ots(
			&builder,
			&domain_param,
			&message,
			&nonce,
			&signature_hashes,
			&public_key_hashes,
			&spec,
		);

		let circuit = builder.build();
		let mut w = circuit.new_witness_filler();

		// Generate test data
		let mut rng = StdRng::seed_from_u64(42);

		// Set up domain_param (18 bytes)
		let mut domain_param_bytes = [0u8; 18];
		rng.fill_bytes(&mut domain_param_bytes);
		// Pad to 24 bytes for packing into 3 wires
		let mut padded_domain_param = vec![0u8; 24];
		padded_domain_param[..18].copy_from_slice(&domain_param_bytes);
		pack_bytes_into_wires_le(&mut w, &domain_param, &padded_domain_param);

		// Set up message (32 bytes)
		let mut message_bytes = [0u8; 32];
		rng.fill_bytes(&mut message_bytes);
		pack_bytes_into_wires_le(&mut w, &message, &message_bytes);

		let grind_result = grind_nonce(&spec, &mut rng, &domain_param_bytes, &message_bytes)
			.expect("Failed to find valid nonce");

		let mut nonce_bytes = grind_result.nonce;
		let tweaked_message = grind_result.tweaked_message;
		let tweaked_message_hash = hash_message(&domain_param_bytes, &nonce_bytes, &message_bytes);
		nonce_bytes.resize(24, 0);

		// Pack nonce into wires (24 bytes, last byte is 0)
		pack_bytes_into_wires_le(&mut w, &nonce, &nonce_bytes);

		// Generate signature and public key hashes
		let mut sig_hashes = Vec::new();
		let mut pk_hashes = Vec::new();

		for (chain_idx, &coord) in grind_result.coords.iter().enumerate() {
			// Generate random signature hash
			let mut sig_hash = [0u8; 32];
			rng.fill_bytes(&mut sig_hash);
			sig_hashes.push(sig_hash);

			// Compute public key hash by hashing forward
			let pk_hash = hash_chain_keccak(
				&domain_param_bytes,
				chain_idx,
				&sig_hash,
				coord as usize,
				spec.chain_len() - 1 - coord as usize,
			);
			pk_hashes.push(pk_hash);

			// Pack into wires
			pack_bytes_into_wires_le(&mut w, &signature_hashes[chain_idx], &sig_hash);
			pack_bytes_into_wires_le(&mut w, &public_key_hashes[chain_idx], &pk_hash);
		}

		result
			.message_hasher
			.populate_message(&mut w, &tweaked_message);
		// Populate the digest (only first 32 bytes needed for SHA3-256)
		result
			.message_hasher
			.populate_digest(&mut w, tweaked_message_hash);

		// Populate chain hashers
		let mut hasher_idx = 0;
		for (chain_idx, &coord) in grind_result.coords.iter().enumerate() {
			let mut current_hash = sig_hashes[chain_idx];

			for step in 0..spec.chain_len() {
				let position = step + coord as usize;
				let position_plus_one = position + 1;

				// Compute next hash
				let next_hash =
					hash_chain_keccak(&domain_param_bytes, chain_idx, &current_hash, position, 1);

				// Populate the Keccak hasher
				let keccak = &result.chain_hashers[hasher_idx];

				let chain_message = build_chain_hash(
					&domain_param_bytes,
					&current_hash,
					chain_idx as u64,
					position_plus_one as u64,
				);
				keccak.populate_message(&mut w, &chain_message);
				// Populate the digest
				keccak.populate_digest(&mut w, next_hash);

				// Update current hash if used
				if position_plus_one < spec.chain_len() {
					current_hash = next_hash;
				}

				hasher_idx += 1;
			}
		}

		// Populate witness and verify
		circuit.populate_wire_witness(&mut w).unwrap();

		let cs = circuit.constraint_system();
		verify_constraints(cs, &w.into_value_vec()).unwrap();
	}
}
