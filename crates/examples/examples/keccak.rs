use anyhow::Result;
use binius_examples::{Cli, circuits::keccak::KeccakExample};

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<KeccakExample>::new("keccak")
		.about("Keccak-f[1600] permutation example - chains multiple permutations together")
		.run()
}
