// Copyright 2025 Irreducible Inc.
pub mod circuits;
pub mod cli;
pub mod snapshot;

use anyhow::Result;
use binius_core::constraint_system::{ConstraintSystem, ValueVec};
use binius_frontend::{CircuitBuilder, WitnessFiller};
use binius_prover::{
	OptimalPackedB128, Prover, hash::parallel_compression::ParallelCompressionAdaptor,
};
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
	transcript::{ProverTranscript, VerifierTranscript},
};
pub use cli::Cli;

pub type StdVerifier = Verifier<StdDigest, StdCompression>;
pub type StdProver =
	Prover<OptimalPackedB128, ParallelCompressionAdaptor<StdCompression>, StdDigest>;

pub fn setup(cs: ConstraintSystem, log_inv_rate: usize) -> Result<(StdVerifier, StdProver)> {
	let _setup_guard = tracing::info_span!("Setup", log_inv_rate).entered();
	let verifier = Verifier::<StdDigest, _>::setup(cs, log_inv_rate, StdCompression::default())?;
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
	)?;
	Ok((verifier, prover))
}

/// Like [`setup`] but skips expensive key collection building.
pub fn setup_with_key_collection(
	cs: ConstraintSystem,
	key_collection: binius_prover::KeyCollection,
	log_inv_rate: usize,
) -> Result<(StdVerifier, StdProver)> {
	let _setup_guard = tracing::info_span!("Setup", log_inv_rate).entered();
	let verifier = Verifier::<StdDigest, _>::setup(cs, log_inv_rate, StdCompression::default())?;
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup_with_key_collection(
		verifier.clone(),
		ParallelCompressionAdaptor::new(StdCompression::default()),
		key_collection,
	)?;
	Ok((verifier, prover))
}

pub fn prove_verify(verifier: &StdVerifier, prover: &StdProver, witness: ValueVec) -> Result<()> {
	let challenger = StdChallenger::default();

	let mut prover_transcript = ProverTranscript::new(challenger.clone());
	prover.prove(witness.clone(), &mut prover_transcript)?;

	let proof = prover_transcript.finalize();
	tracing::info!("Proof size: {} KiB", proof.len() / 1024);

	let mut verifier_transcript = VerifierTranscript::new(challenger, proof);
	verifier.verify(witness.public(), &mut verifier_transcript)?;
	verifier_transcript.finalize()?;

	Ok(())
}

/// Trait for standardizing circuit examples in the Binius framework.
///
/// This trait provides a common pattern for implementing circuit examples by separating:
/// - **Circuit parameters** (`Params`): compile-time configuration that affects circuit structure
/// - **Instance data** (`Instance`): runtime data used to populate the witness
/// - **Circuit building**: logic to construct the circuit based on parameters
/// - **Witness population**: logic to fill in witness values based on instance data
///
/// # Example Implementation
///
/// ```rust,ignore
/// struct MyExample {
///     params: MyParams,
///     // Store any gadgets or wire references needed for witness population
/// }
///
/// #[derive(clap::Args)]
/// struct MyParams {
///     #[arg(long)]
///     max_size: usize,
/// }
///
/// #[derive(clap::Args)]
/// struct MyInstance {
///     #[arg(long)]
///     input_value: Option<String>,
/// }
///
/// impl ExampleCircuit for MyExample {
///     type Params = MyParams;
///     type Instance = MyInstance;
///
///     fn build(params: MyParams, builder: &mut CircuitBuilder) -> Result<Self> {
///         // Construct circuit based on parameters
///         Ok(Self { params })
///     }
///
///     fn populate_witness(&self, instance: MyInstance, filler: &mut WitnessFiller) -> Result<()> {
///         // Fill witness values based on instance data
///         Ok(())
///     }
/// }
/// ```
///
/// # Lifecycle
///
/// 1. Parse CLI arguments to get `Params` and `Instance`
/// 2. Call `build()` with parameters to construct the circuit
/// 3. Build the constraint system
/// 4. Set up prover and verifier
/// 5. Call `populate_witness()` to fill witness values
/// 6. Generate and verify proof
pub trait ExampleCircuit: Sized {
	/// Circuit parameters that affect the structure of the circuit.
	/// These are typically compile-time constants or bounds.
	type Params: clap::Args;

	/// Instance data used to populate the witness.
	/// This represents the actual input values for a specific proof.
	type Instance: clap::Args;

	/// Build the circuit with the given parameters.
	///
	/// This method should:
	/// - Add witnesses, constants, and constraints to the builder
	/// - Store any wire references needed for witness population
	/// - Return a Self instance that can later populate witness values
	fn build(params: Self::Params, builder: &mut CircuitBuilder) -> Result<Self>;

	/// Populate witness values for a specific instance.
	///
	/// This method should:
	/// - Process the instance data (e.g., parse inputs, compute hashes)
	/// - Fill all witness values using the provided filler
	/// - Validate that instance data is compatible with circuit parameters
	fn populate_witness(&self, instance: Self::Instance, filler: &mut WitnessFiller) -> Result<()>;
}
