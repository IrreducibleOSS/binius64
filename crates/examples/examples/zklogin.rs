use anyhow::Result;
use binius_examples::{Cli, circuits::zklogin::ZkLoginExample};

fn main() -> Result<()> {
	let _tracing_guard = tracing_profile::init_tracing()?;

	Cli::<ZkLoginExample>::new("zklogin")
		.about("Circuit verifying knowledge of a valid OpenID Connect login")
		.run()
}
