use anyhow::Result;
use binius_frontend::compiler::CircuitBuilder;
use clap::{Arg, Args, Command, FromArgMatches};

use crate::{ExampleCircuit, prove_verify, setup};

/// A CLI builder for circuit examples that handles all command-line parsing and execution.
///
/// This provides a clean API for circuit examples where developers only need to:
/// 1. Implement the `ExampleCircuit` trait
/// 2. Define their `Params` and `Instance` structs with `#[derive(Args)]`
/// 3. Call `Cli::new("name").run()` in their main function
///
/// # Example
///
/// ```rust,ignore
/// fn main() -> Result<()> {
///     let _tracing_guard = tracing_profile::init_tracing()?;
///
///     Cli::<MyExample>::new("my_circuit")
///         .about("Description of my circuit")
///         .run()
/// }
/// ```
pub struct Cli<E: ExampleCircuit> {
	command: Command,
	_phantom: std::marker::PhantomData<E>,
}

impl<E: ExampleCircuit> Cli<E>
where
	E::Params: Args,
	E::Instance: Args,
{
	/// Create a new CLI for the given circuit example.
	///
	/// The `name` parameter sets the command name (shown in help and usage).
	pub fn new(name: &'static str) -> Self {
		let mut command = Command::new(name);

		// Add common arguments
		command = command.arg(
			Arg::new("log_inv_rate")
				.short('l')
				.long("log-inv-rate")
				.value_name("RATE")
				.help("Log of the inverse rate for the proof system")
				.default_value("1")
				.value_parser(clap::value_parser!(u32).range(1..)),
		);

		// Augment with Params arguments
		command = E::Params::augment_args(command);

		// Augment with Instance arguments
		command = E::Instance::augment_args(command);

		Self {
			command,
			_phantom: std::marker::PhantomData,
		}
	}

	/// Set the about/description text for the command.
	///
	/// This appears in the help output.
	pub fn about(mut self, about: &'static str) -> Self {
		self.command = self.command.about(about);
		self
	}

	/// Set the long about text for the command.
	///
	/// This appears in the detailed help output (--help).
	pub fn long_about(mut self, long_about: &'static str) -> Self {
		self.command = self.command.long_about(long_about);
		self
	}

	/// Set the version information for the command.
	pub fn version(mut self, version: &'static str) -> Self {
		self.command = self.command.version(version);
		self
	}

	/// Set the author information for the command.
	pub fn author(mut self, author: &'static str) -> Self {
		self.command = self.command.author(author);
		self
	}

	/// Run the circuit with parsed ArgMatches.
	fn run_with_matches(matches: clap::ArgMatches) -> Result<()> {
		// Extract common arguments
		let log_inv_rate = *matches
			.get_one::<u32>("log_inv_rate")
			.expect("has default value");

		// Parse Params and Instance from matches
		let params = E::Params::from_arg_matches(&matches)?;
		let instance = E::Instance::from_arg_matches(&matches)?;

		// Build the circuit
		let build_scope = tracing::info_span!("Building circuit").entered();
		let mut builder = CircuitBuilder::new();
		let example = E::build(params, &mut builder)?;
		let circuit = builder.build();
		drop(build_scope);

		// Set up prover and verifier
		let cs = circuit.constraint_system().clone();
		let (verifier, prover) = setup(cs, log_inv_rate as usize)?;

		// Population of the input to the witness and then evaluating the circuit.
		let witness_population = tracing::info_span!("Generating witness").entered();
		let mut filler = circuit.new_witness_filler();
		tracing::info_span!("Input population")
			.in_scope(|| example.populate_witness(instance, &mut filler))?;
		tracing::info_span!("Circuit evaluation")
			.in_scope(|| circuit.populate_wire_witness(&mut filler))?;
		let witness = filler.into_value_vec();
		drop(witness_population);

		// Prove and verify
		prove_verify(&verifier, &prover, witness)?;

		Ok(())
	}

	/// Parse arguments and run the circuit example.
	///
	/// This orchestrates the entire flow:
	/// 1. Parse command-line arguments
	/// 2. Build the circuit using the params
	/// 3. Set up prover and verifier
	/// 4. Generate witness using the instance
	/// 5. Create and verify proof
	pub fn run(self) -> Result<()> {
		let matches = self.command.get_matches();
		Self::run_with_matches(matches)
	}

	/// Parse arguments and run with custom argument strings (useful for testing).
	///
	/// This is similar to `run()` but takes explicit argument strings instead of
	/// reading from `std::env::args()`.
	pub fn run_from<I, T>(self, args: I) -> Result<()>
	where
		I: IntoIterator<Item = T>,
		T: Into<std::ffi::OsString> + Clone,
	{
		let matches = self.command.try_get_matches_from(args)?;
		Self::run_with_matches(matches)
	}
}
