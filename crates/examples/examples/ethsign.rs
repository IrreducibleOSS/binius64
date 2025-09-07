// Copyright 2025 Irreducible Inc.
use anyhow::Result;
use binius_examples::{Cli, circuits::ethsign::EthSignExample};

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<EthSignExample>::new("ethsign")
		.about("Ethereum-style signing example")
		.run()
}
