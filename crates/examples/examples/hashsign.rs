use anyhow::Result;
use binius_examples::{
	Cli,
	circuits::hashsign::{HashBasedSigExample, Instance, Params},
};

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<HashBasedSigExample>::new("hashsign")
		.about("Hash-based multi-signature (XMSS) verification example")
		.run()
}
