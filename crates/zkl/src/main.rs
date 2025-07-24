use std::{fs, path::Path};

use binius_frontend::{
	circuits::zklogin::{Config, ZkLogin},
	compiler::CircuitBuilder,
	util::CircuitStat,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "zkl")]
#[command(about = "ZKLogin circuit tools", long_about = None)]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Parser)]
struct ConfigCli {
	// NOTE: all those fields is a mirror of the zklogin::Config struct.
	//       when updating keep in sync those two.
	/// Maximum byte length of base64 decoded JWT header (must be multiple of 24)
	#[arg(long, value_parser = multiple_of_24)]
	max_len_json_jwt_header: Option<usize>,

	/// Maximum byte length of base64 decoded JWT payload (must be multiple of 24)
	#[arg(long, value_parser = multiple_of_24)]
	max_len_json_jwt_payload: Option<usize>,

	/// Maximum byte length of base64 decoded JWT signature (must be multiple of 24)
	#[arg(long, value_parser = multiple_of_24)]
	max_len_jwt_signature: Option<usize>,

	/// Maximum byte length of JWT sub claim (must be multiple of 8)
	#[arg(long, value_parser = multiple_of_8)]
	max_len_jwt_sub: Option<usize>,

	/// Maximum byte length of JWT aud claim (must be multiple of 8)
	#[arg(long, value_parser = multiple_of_8)]
	max_len_jwt_aud: Option<usize>,

	/// Maximum byte length of JWT iss claim (must be multiple of 8)
	#[arg(long, value_parser = multiple_of_8)]
	max_len_jwt_iss: Option<usize>,

	/// Maximum byte length of salt (must be multiple of 8)
	#[arg(long, value_parser = multiple_of_8)]
	max_len_salt: Option<usize>,

	/// Maximum byte length of nonce r (must be multiple of 8)
	#[arg(long, value_parser = multiple_of_8)]
	max_len_nonce_r: Option<usize>,

	/// Maximum byte length of t_max (must be multiple of 8)
	#[arg(long, value_parser = multiple_of_8)]
	max_len_t_max: Option<usize>,
}

impl ConfigCli {
	fn into_config(self) -> Config {
		let default = Config::default();
		let ConfigCli {
			max_len_json_jwt_header,
			max_len_json_jwt_payload,
			max_len_jwt_signature,
			max_len_jwt_sub,
			max_len_jwt_aud,
			max_len_jwt_iss,
			max_len_salt,
			max_len_nonce_r,
			max_len_t_max,
		} = self;
		Config {
			max_len_json_jwt_header: max_len_json_jwt_header
				.unwrap_or(default.max_len_json_jwt_header),
			max_len_json_jwt_payload: max_len_json_jwt_payload
				.unwrap_or(default.max_len_json_jwt_payload),
			max_len_jwt_signature: max_len_jwt_signature.unwrap_or(default.max_len_jwt_signature),
			max_len_jwt_sub: max_len_jwt_sub.unwrap_or(default.max_len_jwt_sub),
			max_len_jwt_aud: max_len_jwt_aud.unwrap_or(default.max_len_jwt_aud),
			max_len_jwt_iss: max_len_jwt_iss.unwrap_or(default.max_len_jwt_iss),
			max_len_salt: max_len_salt.unwrap_or(default.max_len_salt),
			max_len_nonce_r: max_len_nonce_r.unwrap_or(default.max_len_nonce_r),
			max_len_t_max: max_len_t_max.unwrap_or(default.max_len_t_max),
		}
	}
}

#[derive(Subcommand)]
enum Commands {
	/// Print circuit statistics
	Stat {
		#[command(flatten)]
		config: ConfigCli,
	},
	/// Print the composition of the circuit in JSON format.
	Composition {
		#[command(flatten)]
		config: ConfigCli,
	},
	/// Check circuit statistics against snapshot
	CheckSnapshot,
	/// Bless the snapshot with current circuit statistics.
	BlessSnapshot,
}

fn main() {
	let cli = Cli::parse();

	match cli.command {
		Commands::Stat { config } => {
			print_circuit_stats(config.into_config());
		}
		Commands::Composition { config } => print_circuit_composition(config.into_config()),
		Commands::CheckSnapshot => {
			check_snapshot(Config::default());
		}
		Commands::BlessSnapshot => {
			bless_snapshot(Config::default());
		}
	}
}

fn get_circuit_stats_string(config: Config) -> String {
	let mut output = String::new();
	output.push_str("ZK Login circuit\n");
	output.push_str(&format!("config: {config:#?}\n"));
	output.push_str("--\n");

	let mut builder = CircuitBuilder::new();
	let _zklogin = ZkLogin::new(&mut builder, config);
	let circuit = builder.build();

	let stat = CircuitStat::collect(&circuit);
	output.push_str(&format!("{stat}"));
	output
}

fn print_circuit_stats(config: Config) {
	let output = get_circuit_stats_string(config);
	print!("{output}");
}

fn print_circuit_composition(config: Config) {
	let mut builder = CircuitBuilder::new();
	let _zklogin = ZkLogin::new(&mut builder, config);
	let circuit = builder.build();
	let dump = circuit.simple_json_dump();
	println!("{dump}");
}

fn multiple_of_8(s: &str) -> Result<usize, String> {
	let value: usize = s
		.parse()
		.map_err(|_| format!("'{s}' is not a valid number"))?;
	if !value.is_multiple_of(8) {
		Err(format!("Value {value} must be a multiple of 8"))
	} else {
		Ok(value)
	}
}

fn multiple_of_24(s: &str) -> Result<usize, String> {
	let value: usize = s
		.parse()
		.map_err(|_| format!("'{s}' is not a valid number"))?;
	if !value.is_multiple_of(24) {
		Err(format!("Value {value} must be a multiple of 24"))
	} else {
		Ok(value)
	}
}

const SNAPSHOT_PATH: &str = "crates/zkl/snapshots/stat_output.snap";

fn check_snapshot(config: Config) {
	let snapshot_path = Path::new(SNAPSHOT_PATH);

	if !snapshot_path.exists() {
		eprintln!("Error: Snapshot file not found at {SNAPSHOT_PATH}");
		eprintln!("Run 'cargo run -p zkl -- bless-snapshot' to create it.");
		std::process::exit(1);
	}

	let expected = fs::read_to_string(snapshot_path).unwrap_or_else(|e| {
		eprintln!("Error reading snapshot file: {e}");
		std::process::exit(1);
	});

	let actual = get_circuit_stats_string(config);

	if expected != actual {
		eprintln!("Error: Circuit statistics do not match snapshot!");
		eprintln!("\n--- Expected (from snapshot) ---");
		eprintln!("{expected}");
		eprintln!("\n--- Actual ---");
		eprintln!("{actual}");
		eprintln!("\n--- Diff ---");

		// Simple line-by-line diff
		let expected_lines: Vec<_> = expected.lines().collect();
		let actual_lines: Vec<_> = actual.lines().collect();

		let max_lines = expected_lines.len().max(actual_lines.len());
		for i in 0..max_lines {
			let exp_line = expected_lines.get(i).unwrap_or(&"");
			let act_line = actual_lines.get(i).unwrap_or(&"");

			if exp_line != act_line {
				eprintln!("Line {}: - {}", i + 1, exp_line);
				eprintln!("Line {}: + {}", i + 1, act_line);
			}
		}

		eprintln!("\nRun 'cargo run -p zkl -- bless-snapshot' to update the snapshot.");
		std::process::exit(1);
	}

	println!("✓ Circuit statistics match snapshot");
}

fn bless_snapshot(config: Config) {
	let snapshot_path = Path::new(SNAPSHOT_PATH);

	// Create directory if it doesn't exist
	if let Some(parent) = snapshot_path.parent() {
		fs::create_dir_all(parent).unwrap_or_else(|e| {
			eprintln!("Error creating snapshot directory: {e}");
			std::process::exit(1);
		});
	}

	let output = get_circuit_stats_string(config);

	fs::write(snapshot_path, &output).unwrap_or_else(|e| {
		eprintln!("Error writing snapshot file: {e}");
		std::process::exit(1);
	});

	println!("✓ Snapshot updated at {SNAPSHOT_PATH}");
}
