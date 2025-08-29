use std::{fs, path::Path};

use anyhow::Result;
use binius_core::constraint_system::{ValueVec, ValuesData};
use binius_frontend::{compiler::CircuitBuilder, stat::CircuitStat};
use binius_utils::serialization::SerializeBytes;
use clap::{Arg, Args, Command, FromArgMatches, Subcommand};

use crate::{ExampleCircuit, prove_verify, setup};

/// Serialize a value implementing `SerializeBytes` and write it to the given path.
fn write_serialized<T: SerializeBytes>(value: &T, path: &str) -> Result<()> {
	if let Some(parent) = Path::new(path).parent()
		&& !parent.as_os_str().is_empty()
	{
		fs::create_dir_all(parent).map_err(|e| {
			anyhow::anyhow!("Failed to create directory '{}': {}", parent.display(), e)
		})?;
	}
	let mut buf: Vec<u8> = Vec::new();
	value.serialize(&mut buf)?;
	fs::write(path, &buf)
		.map_err(|e| anyhow::anyhow!("Failed to write serialized data to '{}': {}", path, e))?;
	Ok(())
}

/// A CLI builder for circuit examples that handles all command-line parsing and execution.
///
/// This provides a clean API for circuit examples where developers only need to:
/// 1. Implement the `ExampleCircuit` trait
/// 2. Define their `Params` and `Instance` structs with `#[derive(Args)]`
/// 3. Call `Cli::new("name").run()` in their main function
///
/// The CLI supports multiple subcommands:
/// - `prove` (default): Generate and verify a proof
/// - `stat`: Display circuit statistics
/// - `composition`: Output circuit composition in JSON format
/// - `check-snapshot`: Verify circuit statistics against a snapshot
/// - `bless-snapshot`: Update the snapshot with current statistics
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
	name: String,
	command: Command,
	_phantom: std::marker::PhantomData<E>,
}

/// Subcommands available for circuit examples
#[derive(Subcommand, Clone)]
enum Commands {
	/// Generate and verify a proof (default)
	Prove {
		/// Log of the inverse rate for the proof system
		#[arg(short = 'l', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
		log_inv_rate: u32,

		#[command(flatten)]
		params: CommandArgs,

		#[command(flatten)]
		instance: CommandArgs,
	},

	/// Display circuit statistics
	Stat {
		#[command(flatten)]
		params: CommandArgs,
	},

	/// Output circuit composition in JSON format
	Composition {
		#[command(flatten)]
		params: CommandArgs,
	},

	/// Verify circuit statistics against a snapshot
	CheckSnapshot {
		#[command(flatten)]
		params: CommandArgs,
	},

	/// Update the snapshot with current statistics
	BlessSnapshot {
		#[command(flatten)]
		params: CommandArgs,
	},

	/// Save constraint system, public witness, and non-public data to files if paths are provided
	Save {
		/// Output path for the constraint system binary
		#[arg(long = "cs-path")]
		cs_path: Option<String>,

		/// Output path for the public witness binary
		#[arg(long = "pub-witness-path")]
		pub_witness_path: Option<String>,

		/// Output path for the non-public data (witness + internal) binary
		#[arg(long = "non-pub-data-path")]
		non_pub_data_path: Option<String>,

		#[command(flatten)]
		params: CommandArgs,

		#[command(flatten)]
		instance: CommandArgs,
	},
}

/// Wrapper for dynamic command arguments
#[derive(Args, Clone)]
struct CommandArgs {
	#[arg(skip)]
	_phantom: (),
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
		let command = Command::new(name)
			.subcommand_required(false)
			.arg_required_else_help(false);

		// Build subcommands
		let prove_cmd = Self::build_prove_subcommand();
		let stat_cmd = Self::build_stat_subcommand();
		let composition_cmd = Self::build_composition_subcommand();
		let check_snapshot_cmd = Self::build_check_snapshot_subcommand();
		let bless_snapshot_cmd = Self::build_bless_snapshot_subcommand();
		let save_cmd = Self::build_save_subcommand();

		let command = command
			.subcommand(prove_cmd)
			.subcommand(stat_cmd)
			.subcommand(composition_cmd)
			.subcommand(check_snapshot_cmd)
			.subcommand(bless_snapshot_cmd)
			.subcommand(save_cmd);

		// Also add top-level args for default prove behavior
		let command = command.arg(
			Arg::new("log_inv_rate")
				.short('l')
				.long("log-inv-rate")
				.value_name("RATE")
				.help("Log of the inverse rate for the proof system")
				.default_value("1")
				.value_parser(clap::value_parser!(u32).range(1..)),
		);

		// Augment with Params arguments at top level for default behavior
		let command = E::Params::augment_args(command);
		let command = E::Instance::augment_args(command);

		Self {
			name: name.to_string(),
			command,
			_phantom: std::marker::PhantomData,
		}
	}

	fn build_prove_subcommand() -> Command {
		let mut cmd = Command::new("prove")
			.about("Generate and verify a proof")
			.arg(
				Arg::new("log_inv_rate")
					.short('l')
					.long("log-inv-rate")
					.value_name("RATE")
					.help("Log of the inverse rate for the proof system")
					.default_value("1")
					.value_parser(clap::value_parser!(u32).range(1..)),
			);
		cmd = E::Params::augment_args(cmd);
		cmd = E::Instance::augment_args(cmd);
		cmd
	}

	fn build_stat_subcommand() -> Command {
		let cmd = Command::new("stat").about("Display circuit statistics");
		E::Params::augment_args(cmd)
	}

	fn build_composition_subcommand() -> Command {
		let cmd = Command::new("composition").about("Output circuit composition in JSON format");
		E::Params::augment_args(cmd)
	}

	fn build_check_snapshot_subcommand() -> Command {
		let cmd =
			Command::new("check-snapshot").about("Verify circuit statistics against a snapshot");
		E::Params::augment_args(cmd)
	}

	fn build_bless_snapshot_subcommand() -> Command {
		let cmd =
			Command::new("bless-snapshot").about("Update the snapshot with current statistics");
		E::Params::augment_args(cmd)
	}

	fn build_save_subcommand() -> Command {
		let mut cmd = Command::new("save").about(
			"Save constraint system, public witness, and non-public data to files if paths are provided",
		);
		cmd = cmd
			.arg(
				Arg::new("cs_path")
					.long("cs-path")
					.value_name("PATH")
					.help("Output path for the constraint system binary"),
			)
			.arg(
				Arg::new("pub_witness_path")
					.long("pub-witness-path")
					.value_name("PATH")
					.help("Output path for the public witness binary"),
			)
			.arg(
				Arg::new("non_pub_data_path")
					.long("non-pub-data-path")
					.value_name("PATH")
					.help("Output path for the non-public data (witness + internal) binary"),
			);
		cmd = E::Params::augment_args(cmd);
		cmd = E::Instance::augment_args(cmd);
		cmd
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

	/// Run the circuit with parsed ArgMatches (implementation).
	fn run_with_matches_impl(matches: clap::ArgMatches, circuit_name: &str) -> Result<()> {
		// Check if a subcommand was used
		match matches.subcommand() {
			Some(("prove", sub_matches)) => Self::run_prove(sub_matches.clone()),
			Some(("stat", sub_matches)) => Self::run_stat(sub_matches.clone()),
			Some(("composition", sub_matches)) => Self::run_composition(sub_matches.clone()),
			Some(("check-snapshot", sub_matches)) => {
				Self::run_check_snapshot_impl(sub_matches.clone(), circuit_name)
			}
			Some(("bless-snapshot", sub_matches)) => {
				Self::run_bless_snapshot_impl(sub_matches.clone(), circuit_name)
			}
			Some(("save", sub_matches)) => Self::run_save(sub_matches.clone()),
			Some((cmd, _)) => anyhow::bail!("Unknown subcommand: {}", cmd),
			None => {
				// No subcommand - default to prove behavior for backward compatibility
				Self::run_prove(matches)
			}
		}
	}

	fn run_prove(matches: clap::ArgMatches) -> Result<()> {
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

	fn run_stat(matches: clap::ArgMatches) -> Result<()> {
		// Parse Params from matches
		let params = E::Params::from_arg_matches(&matches)?;

		// Build the circuit
		let mut builder = CircuitBuilder::new();
		let _example = E::build(params, &mut builder)?;
		let circuit = builder.build();

		// Print statistics
		let stat = CircuitStat::collect(&circuit);
		print!("{}", stat);

		Ok(())
	}

	fn run_composition(matches: clap::ArgMatches) -> Result<()> {
		// Parse Params from matches
		let params = E::Params::from_arg_matches(&matches)?;

		// Build the circuit
		let mut builder = CircuitBuilder::new();
		let _example = E::build(params, &mut builder)?;
		let circuit = builder.build();

		// Print composition
		let dump = circuit.simple_json_dump();
		println!("{}", dump);

		Ok(())
	}

	fn run_check_snapshot_impl(matches: clap::ArgMatches, circuit_name: &str) -> Result<()> {
		// Parse Params from matches
		let params = E::Params::from_arg_matches(&matches)?;

		// Build the circuit
		let mut builder = CircuitBuilder::new();
		let _example = E::build(params, &mut builder)?;
		let circuit = builder.build();

		// Check snapshot
		crate::snapshot::check_snapshot(circuit_name, &circuit)?;

		Ok(())
	}

	fn run_bless_snapshot_impl(matches: clap::ArgMatches, circuit_name: &str) -> Result<()> {
		// Parse Params from matches
		let params = E::Params::from_arg_matches(&matches)?;

		// Build the circuit
		let mut builder = CircuitBuilder::new();
		let _example = E::build(params, &mut builder)?;
		let circuit = builder.build();

		// Bless snapshot
		crate::snapshot::bless_snapshot(circuit_name, &circuit)?;

		Ok(())
	}

	fn run_save(matches: clap::ArgMatches) -> Result<()> {
		// Extract optional output paths
		let cs_path = matches.get_one::<String>("cs_path").cloned();
		let pub_witness_path = matches.get_one::<String>("pub_witness_path").cloned();
		let non_pub_data_path = matches.get_one::<String>("non_pub_data_path").cloned();

		// If nothing to save, exit early
		if cs_path.is_none() && pub_witness_path.is_none() && non_pub_data_path.is_none() {
			tracing::info!("No output paths provided; nothing to save");
			return Ok(());
		}

		// Parse Params and Instance
		let params = E::Params::from_arg_matches(&matches)?;
		let instance = E::Instance::from_arg_matches(&matches)?;

		// Build circuit
		let mut builder = CircuitBuilder::new();
		let example = E::build(params, &mut builder)?;
		let circuit = builder.build();

		// Generate witness
		let mut filler = circuit.new_witness_filler();
		example.populate_witness(instance, &mut filler)?;
		circuit.populate_wire_witness(&mut filler)?;
		let witness: ValueVec = filler.into_value_vec();

		// Conditionally write artifacts
		if let Some(path) = cs_path.as_deref() {
			write_serialized(circuit.constraint_system(), path)?;
			tracing::info!("Constraint system saved to '{}'", path);
		}

		if let Some(path) = pub_witness_path.as_deref() {
			let data = ValuesData::from(witness.public());
			write_serialized(&data, path)?;
			tracing::info!("Public witness saved to '{}'", path);
		}

		if let Some(path) = non_pub_data_path.as_deref() {
			let data = ValuesData::from(witness.non_public());
			write_serialized(&data, path)?;
			tracing::info!("Non-public witness saved to '{}'", path);
		}

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
		let name = self.name.clone();
		let matches = self.command.get_matches();
		Self::run_with_matches_impl(matches, &name)
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
		let name = self.name.clone();
		let matches = self.command.try_get_matches_from(args)?;
		Self::run_with_matches_impl(matches, &name)
	}
}
