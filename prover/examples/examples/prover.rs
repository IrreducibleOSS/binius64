// Copyright 2025 Irreducible Inc.
use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use binius_core::constraint_system::{ConstraintSystem, Proof, ValueVec, ValuesData};
use binius_examples::setup;
use binius_utils::serialization::{DeserializeBytes, SerializeBytes};
use binius_verifier::{
	config::{ChallengerWithName, StdChallenger},
	transcript::ProverTranscript,
};
use clap::Parser;

// Embedded test files from test_load_prove directory
const CS_BYTES: &[u8] = include_bytes!("../../../test_load_prove/cs.bin");
const PUB_WITNESS_BYTES: &[u8] = include_bytes!("../../../test_load_prove/pub_witness.bin");
const NON_PUB_DATA_BYTES: &[u8] = include_bytes!("../../../test_load_prove/non_pub_data.bin");

/// Prover CLI: generate a proof from a serialized constraint system and witnesses.
#[derive(Debug, Parser)]
#[command(
	name = "prover",
	about = "Generate and save a proof from CS and witnesses"
)]
struct Args {
	/// Path to the constraint system binary (ignored, using embedded data)
	#[arg(long = "cs-path")]
	cs_path: Option<PathBuf>,

	/// Path to the public values (ValuesData) binary (ignored, using embedded data)
	#[arg(long = "pub-witness-path")]
	pub_witness_path: Option<PathBuf>,

	/// Path to the non-public values (ValuesData) binary (ignored, using embedded data)
	#[arg(long = "non-pub-data-path")]
	non_pub_data_path: Option<PathBuf>,

	/// Log of the inverse rate for the proof system
	#[arg(short = 'l', long = "log-inv-rate", default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
	log_inv_rate: u32,
}

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing().ok();
	let args = Args::parse();

	// DEBUG: Using embedded test files instead of command-line paths
	tracing::info!("Using embedded test files from test_load_prove/");

	// Deserialize constraint system from embedded bytes
	let cs = ConstraintSystem::deserialize(&mut &CS_BYTES[..])
		.context("Failed to deserialize embedded ConstraintSystem")?;

	// Deserialize public values from embedded bytes
	let public = ValuesData::deserialize(&mut &PUB_WITNESS_BYTES[..])
		.context("Failed to deserialize embedded public ValuesData")?;

	// Deserialize non-public values from embedded bytes
	let non_public = ValuesData::deserialize(&mut &NON_PUB_DATA_BYTES[..])
		.context("Failed to deserialize embedded non-public ValuesData")?;

	// Reconstruct the full ValueVec
	// Take ownership of the underlying vectors without extra copies
	let public: Vec<_> = public.into();
	let non_public: Vec<_> = non_public.into();
	let witness = ValueVec::new_from_data(cs.value_vec_layout.clone(), public, non_public)
		.context("Failed to reconstruct ValueVec from provided values")?;

	// Setup prover (verifier is not used here)
	let (_verifier, prover) = setup(cs, args.log_inv_rate as usize)?;

	// Prove
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness, &mut prover_transcript)
		.context("Proving failed")?;
	let transcript = prover_transcript.finalize();

	// Wrap into serializable Proof with a stable challenger type identifier.
	// NOTE: Avoid std::any::type_name for cross-platform stability; use a constant instead.
	let _proof = Proof::owned(transcript, StdChallenger::NAME.to_string());

	Ok(())
}
