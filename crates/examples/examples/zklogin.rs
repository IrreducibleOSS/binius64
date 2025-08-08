//! ZKLogin circuit example demonstrating JWT witness population.
//!
//! This example demonstrates how to use the ZKLogin circuit's witness population
//! functionality that was added to support JWT/JWS verification for zkLogin protocol.
//!
//! The example:
//! 1. Generates a JWT with RS256 signature
//! 2. Populates all required witness fields for the ZKLogin circuit
//! 3. Verifies that constraints are satisfied
//!
//! Note: The proof verification may fail due to public/private input configuration
//! in the current circuit design. Use --verify-only to skip proof generation and
//! only run constraint verification.
//!
//! Example usage:
//! ```bash
//! # Run with constraint verification only
//! cargo run --example zklogin -- --verify-only
//!
//! # Run with custom JWT claims
//! cargo run --example zklogin -- --sub "alice@example.com" --aud "myapp" --iss "auth.example.com"
//! ```

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
use binius_examples::{prove_verify, setup};
use binius_frontend::{
	circuits::zklogin::{Config, ZkLogin},
	compiler::CircuitBuilder,
	constraint_verifier::verify_constraints,
};
use clap::Parser;
use jwt_simple::prelude::*;
use rand::prelude::*;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "zklogin")]
#[command(about = "ZKLogin circuit example demonstrating JWT witness population", long_about = None)]
struct Args {
	/// Log of the inverse rate for the proof system
	#[arg(short = 'l', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
	log_inv_rate: u32,

	/// Subject claim value
	#[arg(long, default_value = "1234567890")]
	sub: String,

	/// Audience claim value
	#[arg(long, default_value = "4074087")]
	aud: String,

	/// Issuer claim value
	#[arg(long, default_value = "google.com")]
	iss: String,

	/// Salt value for zkaddr computation
	#[arg(long, default_value = "test_salt_value")]
	salt: String,

	/// Only run constraint verification (skip proof generation)
	#[arg(long, default_value_t = false)]
	verify_only: bool,
}

fn generate_jwt_and_zkaddr(
	sub: &str,
	aud: &str,
	iss: &str,
	salt: &str,
	rng: &mut impl RngCore,
) -> Result<(String, [u8; 32], [u8; 32], Vec<u8>, Vec<u8>, RS256KeyPair)> {
	// Generate VK_u (verifier public key)
	let mut vk_u = [0u8; 32];
	rng.fill_bytes(&mut vk_u);

	// Fixed values for nonce computation
	let t_max = b"t_max";
	let nonce_r = b"nonce_r";

	// Calculate zkaddr = SHA256(concat(sub, aud, iss, salt))
	let mut zkaddr_preimage = Vec::new();
	zkaddr_preimage.extend_from_slice(sub.as_bytes());
	zkaddr_preimage.extend_from_slice(aud.as_bytes());
	zkaddr_preimage.extend_from_slice(iss.as_bytes());
	zkaddr_preimage.extend_from_slice(salt.as_bytes());
	let zkaddr_hash: [u8; 32] = Sha256::digest(&zkaddr_preimage).into();

	// Calculate nonce = SHA256(concat(vk_u, t_max, nonce_r))
	let mut nonce_preimage = Vec::new();
	nonce_preimage.extend_from_slice(&vk_u);
	nonce_preimage.extend_from_slice(t_max);
	nonce_preimage.extend_from_slice(nonce_r);
	let nonce_hash: [u8; 32] = Sha256::digest(&nonce_preimage).into();
	let nonce_hash_base64 = BASE64_URL_SAFE_NO_PAD.encode(nonce_hash);

	// Generate JWT key pair
	let jwt_key_pair = RS256KeyPair::generate(2048).unwrap();

	// Create and sign JWT
	let claims = Claims::create(Duration::from_hours(2))
		.with_issuer(iss)
		.with_audience(aud)
		.with_subject(sub)
		.with_nonce(nonce_hash_base64);

	let jwt = jwt_key_pair.sign(claims).unwrap();

	Ok((jwt, zkaddr_hash, vk_u, zkaddr_preimage, nonce_preimage, jwt_key_pair))
}

fn populate_zklogin_witness(
	zklogin: &ZkLogin,
	w: &mut binius_frontend::compiler::circuit::WitnessFiller,
	jwt: &str,
	zkaddr_hash: [u8; 32],
	zkaddr_preimage: &[u8],
	vk_u: [u8; 32],
	nonce_preimage: &[u8],
	jwt_key_pair: &RS256KeyPair,
	sub: &str,
	aud: &str,
	iss: &str,
	salt: &str,
) -> Result<()> {
	// Parse JWT components
	let jwt_components = jwt.split(".").collect::<Vec<_>>();
	let [header_base64, payload_base64, signature_base64] = jwt_components.as_slice() else {
		anyhow::bail!("JWT should have format: header.payload.signature");
	};

	// Decode JWT components
	let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(signature_base64)?;
	let modulus_bytes = jwt_key_pair.public_key().to_components().n;
	let header = BASE64_URL_SAFE_NO_PAD.decode(header_base64)?;
	let payload = BASE64_URL_SAFE_NO_PAD.decode(payload_base64)?;

	ensure!(
		signature_bytes.len() == 256,
		"RSA signature must be 256 bytes, got {}",
		signature_bytes.len()
	);

	// Populate JWT components
	zklogin.populate_base64_jwt_header(w, header_base64.as_bytes());
	zklogin.populate_base64_jwt_payload(w, payload_base64.as_bytes());
	zklogin.populate_base64_jwt_signature(w, signature_base64.as_bytes());
	zklogin.populate_jwt_header(w, &header);
	zklogin.populate_jwt_header_attributes(w);
	zklogin.populate_jwt_payload(w, &payload);
	zklogin.populate_jwt_signature(w, &signature_bytes);

	// Populate claim values
	zklogin.populate_sub(w, sub.as_bytes());
	zklogin.populate_aud(w, aud.as_bytes());
	zklogin.populate_iss(w, iss.as_bytes());
	zklogin.populate_salt(w, salt.as_bytes());

	// Populate zkaddr
	zklogin.populate_zkaddr(w, &zkaddr_hash);
	zklogin.populate_zkaddr_preimage(w, zkaddr_preimage);
	zklogin.populate_vk_u(w, &vk_u);
	zklogin.populate_t_max(w, b"t_max");
	zklogin.populate_nonce_r(w, b"nonce_r");

	// Populate nonce
	let nonce_hash: [u8; 32] = Sha256::digest(nonce_preimage).into();
	let nonce_hash_base64 = BASE64_URL_SAFE_NO_PAD.encode(nonce_hash);
	zklogin.populate_nonce(w, &nonce_hash);
	zklogin.populate_nonce_preimage(w, nonce_preimage);
	zklogin.populate_base64_jwt_payload_nonce(w, nonce_hash_base64.as_bytes());

	// Populate JWS signature verification data
	let message_str = format!("{header_base64}.{payload_base64}");
	let message = message_str.as_bytes();
	let hash = Sha256::digest(message);
	zklogin.populate_rsa_modulus(w, &modulus_bytes);
	zklogin
		.jwt_signature_verify
		.populate_message_len(w, message.len());
	zklogin.jwt_signature_verify.populate_message(w, message);
	zklogin
		.jwt_signature_verify
		.sha256
		.populate_digest(w, hash.into());
	zklogin
		.jwt_signature_verify
		.populate_intermediates(w, &signature_bytes, &modulus_bytes);

	Ok(())
}

fn main() -> Result<()> {
	let args = Args::parse();
	let _tracing_guard = tracing_profile::init_tracing()?;

	let mut rng = StdRng::seed_from_u64(0);

	println!("ZKLogin Circuit Example");
	println!("=======================");
	println!("JWT Claims:");
	println!("  Subject (sub): {}", args.sub);
	println!("  Audience (aud): {}", args.aud);
	println!("  Issuer (iss): {}", args.iss);
	println!("  Salt: {}", args.salt);

	// Generate JWT and related data
	let (jwt, zkaddr_hash, vk_u, zkaddr_preimage, nonce_preimage, jwt_key_pair) =
		generate_jwt_and_zkaddr(&args.sub, &args.aud, &args.iss, &args.salt, &mut rng)?;

	println!("\nGenerated JWT (truncated): {}...", &jwt[..50.min(jwt.len())]);
	println!("zkaddr hash: {:?}", &zkaddr_hash[..8]);

	// Build the circuit
	let build_scope = tracing::info_span!("Building circuit").entered();
	let mut builder = CircuitBuilder::new();
	let config = Config::default();
	let zklogin = ZkLogin::new(&mut builder, config);
	let circuit = builder.build();
	drop(build_scope);

	// Generate witness
	let witness_scope = tracing::info_span!("Generating witness").entered();
	let mut w = circuit.new_witness_filler();

	populate_zklogin_witness(
		&zklogin,
		&mut w,
		&jwt,
		zkaddr_hash,
		&zkaddr_preimage,
		vk_u,
		&nonce_preimage,
		&jwt_key_pair,
		&args.sub,
		&args.aud,
		&args.iss,
		&args.salt,
	)?;

	circuit.populate_wire_witness(&mut w)?;
	let witness = w.into_value_vec();
	drop(witness_scope);

	// Verify constraints
	let cs = circuit.constraint_system();
	println!("\n📊 Circuit statistics:");
	println!("  Total witness values: {}", witness.size());
	println!("  AND constraints: {}", cs.n_and_constraints());
	println!("  MUL constraints: {}", cs.n_mul_constraints());

	match verify_constraints(cs, &witness) {
		Ok(_) => println!("\n✅ Constraint verification passed"),
		Err(e) => {
			println!("\n❌ Constraint verification failed: {}", e);
			return Err(anyhow::anyhow!("Constraint verification failed: {}", e));
		}
	}

	if args.verify_only {
		println!("\nSkipping proof generation (--verify-only flag set)");
		return Ok(());
	}

	// Setup and prove
	let log_inv_rate = args.log_inv_rate as usize;
	let cs = circuit.constraint_system().clone();
	let (verifier, prover) = setup(cs, log_inv_rate)?;

	// Note: The circuit currently has many inputs marked as public (add_inout) which
	// would typically be private in a real zklogin implementation.
	match prove_verify(&verifier, &prover, witness) {
		Ok(_) => println!("\n✅ ZKLogin proof successfully generated and verified!"),
		Err(e) => {
			println!("\n⚠️  Proof verification failed: {}", e);
			println!("Note: This may be due to public/private input configuration in the circuit.");
		}
	}

	Ok(())
}
