use anyhow::Result;
use binius_examples::{Cli, circuits::ethsign::EthSignExample};

fn main() -> Result<()> {
	Cli::<EthSignExample>::new("ethsign")
		.about("Ethereum-style signing example")
		.with_repeat()
		.run()
}
