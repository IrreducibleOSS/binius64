use std::fmt::Write;

#[derive(Debug, Clone)]
pub struct FeatureInfo {
	pub name: String,
	pub supported_by_platform: bool,
	pub supported_by_binary: bool,
}

impl FeatureInfo {
	fn new(
		name: impl Into<String>,
		supported_by_platform: bool,
		supported_by_binary: bool,
	) -> Self {
		Self {
			name: name.into(),
			supported_by_platform,
			supported_by_binary,
		}
	}

	fn is_enabled(&self) -> bool {
		self.supported_by_platform && self.supported_by_binary
	}
}

/// Get all platform features for the current architecture
pub fn get_platform_features() -> Vec<FeatureInfo> {
	let mut features = Vec::new();

	// Threading feature
	features.push(FeatureInfo::new(
		"rayon",
		true, // Platform always supports threading
		cfg!(feature = "rayon"),
	));

	#[cfg(target_arch = "x86_64")]
	{
		features.push(FeatureInfo::new(
			"gfni",
			std::is_x86_feature_detected!("gfni"),
			cfg!(target_feature = "gfni"),
		));
		features.push(FeatureInfo::new(
			"pclmulqdq",
			std::is_x86_feature_detected!("pclmulqdq"),
			cfg!(target_feature = "pclmulqdq"),
		));
		features.push(FeatureInfo::new(
			"avx2",
			std::is_x86_feature_detected!("avx2"),
			cfg!(target_feature = "avx2"),
		));
		features.push(FeatureInfo::new(
			"avx512f",
			std::is_x86_feature_detected!("avx512f"),
			cfg!(target_feature = "avx512f"),
		));
		features.push(FeatureInfo::new(
			"aes",
			std::is_x86_feature_detected!("aes"),
			cfg!(target_feature = "aes"),
		));
		features.push(FeatureInfo::new(
			"vaes",
			std::is_x86_feature_detected!("vaes"),
			cfg!(target_feature = "vaes"),
		));
		features.push(FeatureInfo::new(
			"vpclmulqdq",
			std::is_x86_feature_detected!("vpclmulqdq"),
			cfg!(target_feature = "vpclmulqdq"),
		));
	}

	#[cfg(target_arch = "aarch64")]
	{
		// For ARM64, we can't detect features at runtime easily, so assume platform support
		// matches what was compiled in
		features.push(FeatureInfo::new(
			"neon",
			cfg!(target_feature = "neon"),
			cfg!(target_feature = "neon"),
		));
		features.push(FeatureInfo::new(
			"aes",
			cfg!(target_feature = "aes"),
			cfg!(target_feature = "aes"),
		));
		features.push(FeatureInfo::new(
			"sha2",
			cfg!(target_feature = "sha2"),
			cfg!(target_feature = "sha2"),
		));
		features.push(FeatureInfo::new(
			"sha3",
			cfg!(target_feature = "sha3"),
			cfg!(target_feature = "sha3"),
		));
		features.push(FeatureInfo::new(
			"pmull",
			cfg!(target_feature = "aes"), // PMULL comes with AES on ARM64
			cfg!(target_feature = "aes"),
		));
	}

	features
}

/// Verify that optimal platform features are enabled at compile time
pub fn verify_platform_features() {
	let features = get_platform_features();

	#[cfg(target_arch = "x86_64")]
	{
		for feature in &features {
			if feature.supported_by_platform && !feature.supported_by_binary {
				match feature.name.as_str() {
					"gfni" => eprintln!(
						"⚠️  WARNING: GFNI not enabled. Use RUSTFLAGS=\"-C target-cpu=native\" for optimal performance on modern Intel CPUs (C7i)"
					),
					"pclmulqdq" => eprintln!(
						"⚠️  WARNING: PCLMULQDQ not enabled. Carryless multiplication will be slower"
					),
					"avx2" => {
						eprintln!("⚠️  WARNING: AVX2 not enabled. SIMD operations will be slower")
					}
					"avx512f" => eprintln!(
						"⚠️  WARNING: AVX-512 not enabled. Performance may be suboptimal on modern Intel CPUs"
					),
					_ => {}
				}
			}
		}
	}

	#[cfg(target_arch = "aarch64")]
	{
		for feature in &features {
			if feature.supported_by_platform && !feature.supported_by_binary {
				match feature.name.as_str() {
					"neon" => eprintln!(
						"⚠️  WARNING: NEON not enabled. Use RUSTFLAGS=\"-C target-cpu=native\" for optimal performance on ARM64 (C8g)"
					),
					"aes" => eprintln!("⚠️  WARNING: AES acceleration not enabled"),
					"sha2" => eprintln!("⚠️  WARNING: SHA2 acceleration not enabled"),
					_ => {}
				}
			}
		}
	}
}

/// Generate a feature suffix for benchmark names
pub fn get_feature_suffix() -> String {
	let features = get_platform_features();
	let mut suffix_parts = Vec::new();

	// Threading
	let rayon = features.iter().find(|f| f.name == "rayon");
	if let Some(rayon) = rayon {
		suffix_parts.push(if rayon.is_enabled() { "mt" } else { "st" });
	}

	// Architecture
	#[cfg(target_arch = "x86_64")]
	{
		suffix_parts.push("x86");

		// Add key features for x86_64
		if let Some(gfni) = features.iter().find(|f| f.name == "gfni") {
			if gfni.is_enabled() {
				suffix_parts.push("gfni");
			}
		}

		// Prefer AVX512 over AVX2 in suffix
		if let Some(avx512) = features.iter().find(|f| f.name == "avx512f") {
			if avx512.is_enabled() {
				suffix_parts.push("avx512");
			} else if let Some(avx2) = features.iter().find(|f| f.name == "avx2") {
				if avx2.is_enabled() {
					suffix_parts.push("avx2");
				}
			}
		}
	}

	#[cfg(target_arch = "aarch64")]
	{
		suffix_parts.push("arm64");

		// Check for NEON and AES together
		let neon = features.iter().find(|f| f.name == "neon");
		let aes = features.iter().find(|f| f.name == "aes");

		if let (Some(neon), Some(aes)) = (neon, aes) {
			if neon.is_enabled() && aes.is_enabled() {
				suffix_parts.push("neon_aes");
			} else if neon.is_enabled() {
				suffix_parts.push("neon");
			}
		}
	}

	suffix_parts.join("_")
}

/// Print platform configuration header
pub fn print_platform_header() {
	println!("\n=== Benchmark Configuration ===");
	println!("Platform: {}", std::env::consts::ARCH);

	let features = get_platform_features();

	// Threading configuration
	if let Some(rayon) = features.iter().find(|f| f.name == "rayon") {
		println!(
			"Threading: {}",
			if rayon.is_enabled() {
				"multi-threaded (rayon)"
			} else {
				"single-threaded"
			}
		);
	}

	// Platform-specific features
	#[cfg(target_arch = "x86_64")]
	{
		println!("\nx86_64 Features:");
		println!("  Feature      Platform  Binary");
		println!("  ----------   --------  ------");

		let x86_features = [
			"gfni",
			"pclmulqdq",
			"avx2",
			"avx512f",
			"aes",
			"vaes",
			"vpclmulqdq",
		];
		for feat_name in &x86_features {
			if let Some(feat) = features.iter().find(|f| f.name == *feat_name) {
				let platform_mark = if feat.supported_by_platform {
					"✓"
				} else {
					"✗"
				};
				let binary_mark = if feat.supported_by_binary {
					"✓"
				} else {
					"✗"
				};
				let display_name = match *feat_name {
					"pclmulqdq" => "PCLMULQDQ".to_string(),
					"vpclmulqdq" => "VPCLMULQDQ".to_string(),
					"avx512f" => "AVX-512".to_string(),
					name => name.to_uppercase(),
				};
				println!("  {:<12} {:^8}  {:^6}", display_name, platform_mark, binary_mark);
			}
		}
	}

	#[cfg(target_arch = "aarch64")]
	{
		println!("\nARM64 Features:");
		println!("  Feature      Platform  Binary");
		println!("  ----------   --------  ------");

		let arm_features = ["neon", "aes", "sha2", "sha3", "pmull"];
		for feat_name in &arm_features {
			if let Some(feat) = features.iter().find(|f| f.name == *feat_name) {
				let platform_mark = if feat.supported_by_platform {
					"✓"
				} else {
					"✗"
				};
				let binary_mark = if feat.supported_by_binary {
					"✓"
				} else {
					"✗"
				};
				let display_name = match *feat_name {
					"pmull" => "PMULL".to_string(),
					name => name.to_uppercase(),
				};
				let suffix = if *feat_name == "pmull" && feat.is_enabled() {
					" (via AES)"
				} else {
					""
				};
				println!(
					"  {:<12} {:^8}  {:^6}{}",
					display_name, platform_mark, binary_mark, suffix
				);
			}
		}
	}
}

/// Format benchmark-specific parameters as a string
pub fn format_benchmark_params(params: &[(&str, String)]) -> String {
	let mut output = String::new();
	for (name, value) in params {
		writeln!(&mut output, "{}: {}", name, value).unwrap();
	}
	output
}

/// Print complete benchmark configuration
pub fn print_benchmark_config(benchmark_name: &str, params: &[(&str, String)]) {
	print_platform_header();
	println!("\n{} Parameters:", benchmark_name);
	print!("{}", format_benchmark_params(params));
	println!("=======================================\n");
}
