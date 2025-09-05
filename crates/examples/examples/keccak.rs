use anyhow::Result;
use binius_examples::{Cli, circuits::keccak::KeccakExample};

fn main() -> Result<()> {
	Cli::<KeccakExample>::new("keccak")
		.about("Keccak-f[1600] permutation example - chains multiple permutations together")
		.with_repeat()
		.run()
}
