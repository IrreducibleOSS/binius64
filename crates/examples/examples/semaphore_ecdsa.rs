use anyhow::Result;
use binius_examples::{Cli, circuits::semaphore_ecdsa::SemaphoreExample};

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<SemaphoreExample>::new("semaphore_ecdsa")
		.about("Anonymous group membership proofs with nullifiers using ECDSA key derivation")
		.run()
}
