use anyhow::Result;
use binius_examples::{Cli, circuits::sha256::Sha256Example};

fn main() -> Result<()> {
	Cli::<Sha256Example>::new("sha256")
		.about("SHA256 compression function example")
		.with_repeat()
		.run()
}
