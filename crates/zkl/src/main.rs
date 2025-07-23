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

#[derive(Subcommand)]
enum Commands {
	/// Print circuit statistics
	Stat {
		// NOTE: all those fields is a mirror of the zklogin::Config struct.
		//       when updating keep in sync those two.
		/// Maximum byte length of base64 decoded JWT header (must be multiple of 24)
		#[arg(long, default_value_t = 264, value_parser = multiple_of_24)]
		max_len_json_jwt_header: usize,

		/// Maximum byte length of base64 decoded JWT payload (must be multiple of 24)
		#[arg(long, default_value_t = 504, value_parser = multiple_of_24)]
		max_len_json_jwt_payload: usize,

		/// Maximum byte length of base64 decoded JWT signature (must be multiple of 24)
		#[arg(long, default_value_t = 264, value_parser = multiple_of_24)]
		max_len_jwt_signature: usize,

		/// Maximum byte length of JWT sub claim (must be multiple of 8)
		#[arg(long, default_value_t = 72, value_parser = multiple_of_8)]
		max_len_jwt_sub: usize,

		/// Maximum byte length of JWT aud claim (must be multiple of 8)
		#[arg(long, default_value_t = 72, value_parser = multiple_of_8)]
		max_len_jwt_aud: usize,

		/// Maximum byte length of JWT iss claim (must be multiple of 8)
		#[arg(long, default_value_t = 72, value_parser = multiple_of_8)]
		max_len_jwt_iss: usize,

		/// Maximum byte length of salt (must be multiple of 8)
		#[arg(long, default_value_t = 72, value_parser = multiple_of_8)]
		max_len_salt: usize,

		/// Maximum byte length of nonce r (must be multiple of 8)
		#[arg(long, default_value_t = 48, value_parser = multiple_of_8)]
		max_len_nonce_r: usize,

		/// Maximum byte length of t_max (must be multiple of 8)
		#[arg(long, default_value_t = 48, value_parser = multiple_of_8)]
		max_len_t_max: usize,
	},
}

fn main() {
	let cli = Cli::parse();

	match cli.command {
		Commands::Stat {
			max_len_json_jwt_header,
			max_len_json_jwt_payload,
			max_len_jwt_signature,
			max_len_jwt_sub,
			max_len_jwt_aud,
			max_len_jwt_iss,
			max_len_salt,
			max_len_nonce_r,
			max_len_t_max,
		} => {
			let config = Config {
				max_len_json_jwt_header,
				max_len_json_jwt_payload,
				max_len_jwt_signature,
				max_len_jwt_sub,
				max_len_jwt_aud,
				max_len_jwt_iss,
				max_len_salt,
				max_len_nonce_r,
				max_len_t_max,
			};

			print_circuit_stats(config);
		}
	}
}

fn print_circuit_stats(config: Config) {
	println!("ZK Login circuit");
	println!("config: {config:#?}");
	println!("--");

	let mut builder = CircuitBuilder::new();
	let _zklogin = ZkLogin::new(&mut builder, config);
	let circuit = builder.build();

	let stat = CircuitStat::collect(&circuit);
	println!("{stat}");
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
