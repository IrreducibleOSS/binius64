// Copyright 2025 Irreducible Inc.
use anyhow::Result;
use binius_examples::{Cli, circuits::sha512::Sha512Example};

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<Sha512Example>::new("sha512")
		.about("SHA512 compression function example")
		.run()
}
