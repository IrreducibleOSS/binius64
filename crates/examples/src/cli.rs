use std::{
	fs,
	path::{Path, PathBuf},
};

use anyhow::Result;
use binius_core::constraint_system::{ValueVec, ValuesData};
use binius_frontend::{
	compiler::{CircuitBuilder, circuit::Circuit},
	stat::CircuitStat,
};
use binius_utils::serialization::SerializeBytes;
use clap::{Arg, Args, Command, FromArgMatches, Subcommand};
#[cfg(feature = "perfetto")]
use tracing_profile::{TraceFilenameBuilder, init_tracing_with_builder};

use crate::{ExampleCircuit, json_export};

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
	repeat_enabled: bool,
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

		/// Number of times to run the benchmark (default: 1 for no repetition)
		#[arg(long, default_value = "1")]
		repeat: usize,

		/// Export metrics to JSON file (optional path, defaults to <benchmark>_metrics.json)
		#[arg(long, value_name = "PATH")]
		json: Option<Option<PathBuf>>,

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
	E::Params: Args + Clone,
	E::Instance: Args + Clone,
{
	/// Common arguments for prove operations (both default and explicit subcommand)
	fn common_prove_args() -> Vec<Arg> {
		vec![
			Arg::new("repeat")
				.long("repeat")
				.value_name("COUNT")
				.help("Number of times to run the benchmark (default: 1 for no repetition)")
				.default_value("1")
				.value_parser(clap::value_parser!(usize)),
			Arg::new("json")
				.long("json")
				.value_name("PATH")
				.help(
					"Export metrics to JSON file (optional path, defaults to <benchmark>_metrics.json)",
				)
				.action(clap::ArgAction::Set)
				.num_args(0..=1)
				.require_equals(false)
				.value_parser(clap::value_parser!(PathBuf)),
		]
	}

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
			repeat_enabled: false,
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

		// Add common prove arguments (--repeat and --json)
		for arg in Self::common_prove_args() {
			cmd = cmd.arg(arg);
		}

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

	/// Enable repeat functionality with --repeat and --json arguments.
	pub fn with_repeat(mut self) -> Self {
		self.repeat_enabled = true;

		// Add common prove arguments to top-level command for default prove behavior
		for arg in Self::common_prove_args() {
			self.command = self.command.arg(arg);
		}

		self
	}

	/// Run the circuit with parsed ArgMatches (implementation).
	fn run_with_matches_impl(
		matches: clap::ArgMatches,
		repeat_enabled: bool,
		circuit_name: &str,
	) -> Result<()> {
		// Check if a subcommand was used
		match matches.subcommand() {
			Some(("prove", sub_matches)) => {
				Self::run_prove(sub_matches.clone(), repeat_enabled, circuit_name)
			}
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
				Self::run_prove(matches, repeat_enabled, circuit_name)
			}
		}
	}


	/// Build circuit and example from parameters
	fn build_circuit_and_example(params: E::Params) -> Result<(Circuit, E)> {
		let build_scope = tracing::info_span!("Building circuit").entered();
		let mut builder = CircuitBuilder::new();
		let example = E::build(params, &mut builder)?;
		let circuit = builder.build();
		drop(build_scope);
		Ok((circuit, example))
	}

	/// Generate witness from circuit, example, and instance
	fn generate_witness(circuit: &Circuit, example: E, instance: E::Instance) -> Result<ValueVec> {
		let witness_scope = tracing::info_span!("Generating witness").entered();
		let mut filler = circuit.new_witness_filler();
		tracing::info_span!("Input population")
			.in_scope(|| example.populate_witness(instance, &mut filler))?;
		tracing::info_span!("Circuit evaluation")
			.in_scope(|| circuit.populate_wire_witness(&mut filler))?;
		let witness = filler.into_value_vec();
		drop(witness_scope);
		Ok(witness)
	}

	/// Run single prove iteration with optional timing collection
	fn run_single_prove_with_timing(
		log_inv_rate: u32,
		params: E::Params,
		instance: E::Instance,
		collect_timing: bool,
	) -> Result<Option<json_export::ProveMetrics>> {
		use std::time::Instant;

		// Build the circuit
		let build_start = if collect_timing {
			Some(Instant::now())
		} else {
			None
		};
		let (circuit, example) = Self::build_circuit_and_example(params)?;

		// Set up prover and verifier
		let cs = circuit.constraint_system().clone();
		let (verifier, prover) = crate::setup(cs, log_inv_rate as usize)?;
		let build_time = build_start.map(|start| start.elapsed());

		// Generate witness
		let witness_start = if collect_timing {
			Some(Instant::now())
		} else {
			None
		};
		let witness = Self::generate_witness(&circuit, example, instance)?;
		let witness_time = witness_start.map(|start| start.elapsed());

		// Prove and verify
		if collect_timing {
			let (prove_time, verify_time, proof_size) =
				crate::prove_verify_timed(&verifier, &prover, witness)?;

			Ok(Some(json_export::ProveMetrics {
				build_time: build_time.unwrap(),
				witness_time: witness_time.unwrap(),
				prove_time,
				verify_time,
				proof_size,
			}))
		} else {
			crate::prove_verify(&verifier, &prover, witness)?;
			Ok(None)
		}
	}

	fn run_prove(
		matches: clap::ArgMatches,
		repeat_enabled: bool,
		circuit_name: &str,
	) -> Result<()> {
		// Extract common arguments
		let log_inv_rate = *matches
			.get_one::<u32>("log_inv_rate")
			.expect("has default value");

		// Check for repeat arguments (only if repeat mode was enabled)
		let repeat_count = if repeat_enabled {
			matches.get_one::<usize>("repeat").copied().unwrap_or(1)
		} else {
			1
		};

		// Handle --json flag for metric export
		let json_path = if repeat_enabled && matches.contains_id("json") {
			Some(matches.get_one::<PathBuf>("json").cloned())
		} else {
			None
		};

		// Parse Params and Instance from matches
		let params = E::Params::from_arg_matches(&matches)?;
		let instance = E::Instance::from_arg_matches(&matches)?;

		// Generate perfetto builder once for this session (same logic for JSON and non-JSON)
		#[cfg(feature = "perfetto")]
		let perfetto_path_builder = if repeat_enabled {
			Some({
				let mut builder = TraceFilenameBuilder::for_benchmark(circuit_name)
					.output_dir("perfetto_traces")
					.timestamp()
					.git_info()
					.platform();

				// Only add subdirectories if running multiple iterations
				if repeat_count > 1 {
					builder = builder.subdir(circuit_name).subdir_run_id();
				}

				if let Some(param_summary) = E::param_summary(&params) {
					builder = builder.add("params", param_summary);
				}

				builder
			})
		} else {
			None
		};

		let mut all_metrics = if json_path.is_some() {
			Some(Vec::new())
		} else {
			None
		};

		// Run iterations with unified logic
		for i in 1..=repeat_count {
			if repeat_enabled && repeat_count > 1 {
				println!("Running iteration {}/{}...", i, repeat_count);
			}

			// Set up perfetto tracing for this iteration if needed
			#[cfg(feature = "perfetto")]
			let _tracing_guard = if let Some(ref builder) = perfetto_path_builder {
				let mut builder_for_iteration = builder.clone();
				if repeat_count > 1 {
					builder_for_iteration = builder_for_iteration.iteration(i);
				}
				init_tracing_with_builder(builder_for_iteration).ok()
			} else {
				None
			};

			// Run single prove - collect timing only if JSON export is needed
			let collect_timing = all_metrics.is_some();
			let prove_metrics = Self::run_single_prove_with_timing(
				log_inv_rate,
				params.clone(),
				instance.clone(),
				collect_timing,
			)?;

			// Store metrics if JSON export is requested
			if let (Some(metrics), Some(prove_metrics)) = (&mut all_metrics, prove_metrics) {
				metrics.push(json_export::RunMetrics {
					iteration: if repeat_count > 1 { Some(i) } else { None },
					build_ms: prove_metrics.build_time.as_secs_f64() * 1000.0,
					witness_ms: prove_metrics.witness_time.as_secs_f64() * 1000.0,
					prove_ms: prove_metrics.prove_time.as_secs_f64() * 1000.0,
					verify_ms: prove_metrics.verify_time.as_secs_f64() * 1000.0,
					proof_size_bytes: prove_metrics.proof_size,
				});
			}
		}

		if repeat_enabled && repeat_count > 1 {
			println!("Done.");
		}

		// Export metrics to JSON if requested
		if let (Some(json_path_option), Some(all_metrics)) = (json_path, all_metrics) {
			let json_path = json_path_option.unwrap_or_else(|| {
				std::path::PathBuf::from(format!("{}_metrics.json", circuit_name))
			});

			json_export::export_metrics(
				circuit_name,
				E::param_summary(&params),
				log_inv_rate,
				all_metrics,
				json_path,
			)?;
		}

		Ok(())
	}

	/// Helper to run commands that only need circuit (no witness)
	fn run_with_circuit<F>(matches: clap::ArgMatches, action: F) -> Result<()>
	where
		F: FnOnce(&Circuit) -> Result<()>,
	{
		let params = E::Params::from_arg_matches(&matches)?;
		let (circuit, _example) = Self::build_circuit_and_example(params)?;
		action(&circuit)
	}

	fn run_stat(matches: clap::ArgMatches) -> Result<()> {
		Self::run_with_circuit(matches, |circuit| {
			let stat = CircuitStat::collect(circuit);
			print!("{}", stat);
			Ok(())
		})
	}

	fn run_composition(matches: clap::ArgMatches) -> Result<()> {
		Self::run_with_circuit(matches, |circuit| {
			let dump = circuit.simple_json_dump();
			println!("{}", dump);
			Ok(())
		})
	}

	fn run_check_snapshot_impl(matches: clap::ArgMatches, circuit_name: &str) -> Result<()> {
		Self::run_with_circuit(matches, |circuit| {
			crate::snapshot::check_snapshot(circuit_name, circuit)
		})
	}

	fn run_bless_snapshot_impl(matches: clap::ArgMatches, circuit_name: &str) -> Result<()> {
		Self::run_with_circuit(matches, |circuit| {
			crate::snapshot::bless_snapshot(circuit_name, circuit)
		})
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

		// Build circuit and generate witness using helper functions
		let (circuit, example) = Self::build_circuit_and_example(params)?;
		let witness = Self::generate_witness(&circuit, example, instance)?;

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
		let repeat_enabled = self.repeat_enabled;
		let name = self.name.clone();
		let matches = self.command.get_matches();
		Self::run_with_matches_impl(matches, repeat_enabled, &name)
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
		let repeat_enabled = self.repeat_enabled;
		let name = self.name.clone();
		let matches = self.command.try_get_matches_from(args)?;
		Self::run_with_matches_impl(matches, repeat_enabled, &name)
	}
}
