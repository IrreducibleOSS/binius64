use std::env;
use std::path::PathBuf;
use std::fs::File;
use std::io::Write;

fn main() -> std::io::Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(&out_dir).join("platform_build_info.rs");
    let mut f = File::create(&dest_path)?;

    // Collect all CARGO_CFG_* variables
    let mut cfg_vars = Vec::new();
    let mut target_features = Vec::new();
    
    for (key, value) in env::vars() {
        if key.starts_with("CARGO_CFG_") {
            cfg_vars.push((key.clone(), value.clone()));
            
            // CARGO_CFG_TARGET_FEATURE contains comma-separated features
            if key == "CARGO_CFG_TARGET_FEATURE" && !value.is_empty() {
                target_features = value.split(',').map(|s| s.to_string()).collect();
            }
        }
    }
    cfg_vars.sort();

    // Generate compile-time constants
    writeln!(f, "pub const BUILD_TARGET: &str = {:?};", env::var("TARGET").unwrap())?;
    writeln!(f, "pub const BUILD_HOST: &str = {:?};", env::var("HOST").unwrap())?;
    writeln!(f, "pub const BUILD_PROFILE: &str = {:?};", env::var("PROFILE").unwrap())?;
    // Cargo may use CARGO_ENCODED_RUSTFLAGS instead of RUSTFLAGS
    let rustflags = env::var("CARGO_ENCODED_RUSTFLAGS")
        .or_else(|_| env::var("RUSTFLAGS"))
        .unwrap_or_default()
        .replace('\x1f', " "); // CARGO_ENCODED_RUSTFLAGS uses 0x1f as separator
    writeln!(f, "pub const BUILD_RUSTFLAGS: &str = {:?};", rustflags)?;
    
    // Generate feature array
    writeln!(f, "\npub const COMPILE_TIME_FEATURES: &[&str] = &[")?;
    for feature in &target_features {
        writeln!(f, "    {:?},", feature)?;
    }
    writeln!(f, "];")?;
    
    // Generate all cfg variables
    writeln!(f, "\npub const CFG_VARIABLES: &[(&str, &str)] = &[")?;
    for (key, value) in &cfg_vars {
        writeln!(f, "    ({:?}, {:?}),", key, value)?;
    }
    writeln!(f, "];")?;

    // Print build-time warnings for visibility
    println!("cargo:warning=Platform Build Configuration:");
    println!("cargo:warning=  Target: {}", env::var("TARGET").unwrap());
    println!("cargo:warning=  Host: {}", env::var("HOST").unwrap());
    println!("cargo:warning=  RUSTFLAGS: {}", rustflags);
    println!("cargo:warning=  Features detected: {}", target_features.len());

    Ok(())
}