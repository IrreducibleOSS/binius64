use anyhow::Result;
use binius_core::constraint_system::{ConstraintSystem, ValueVec};
use binius_prover::{OptimalPackedB128, Prover};
use binius_verifier::{
	Verifier,
	config::StdChallenger,
	hash::{StdCompression, StdDigest},
	transcript::ProverTranscript,
};

pub type StdVerifier = Verifier<StdDigest, StdCompression>;
pub type StdProver = Prover<OptimalPackedB128, StdCompression, StdDigest>;

pub fn setup(cs: ConstraintSystem, log_inv_rate: usize) -> Result<(StdVerifier, StdProver)> {
	let _scope = tracing::info_span!("Setup", log_inv_rate).entered();
	let verifier = Verifier::<StdDigest, _>::setup(cs, log_inv_rate, StdCompression::default())?;
	let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(verifier.clone())?;
	Ok((verifier, prover))
}

pub fn prove_verify(verifier: &StdVerifier, prover: &StdProver, witness: ValueVec) -> Result<()> {
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	tracing::info_span!("Proving")
		.in_scope(|| prover.prove(witness.clone(), &mut prover_transcript))?;

	let mut verifier_transcript = prover_transcript.into_verifier();
	tracing::info_span!("Verifying")
		.in_scope(|| verifier.verify(witness.public(), &mut verifier_transcript))?;
	verifier_transcript.finalize()?;

	Ok(())
}
