use std::env;
use std::path::{Path, PathBuf};

fn main() {
    // Tell Cargo about our custom cfg flags
    println!("cargo::rustc-check-cfg=cfg(has_binius_prover)");
    println!("cargo::rustc-check-cfg=cfg(no_binius_prover)");
    
    // Skip library detection when we're building the FFI implementation itself
    // This avoids circular dependency when building as cdylib
    if env::var("CARGO_FEATURE_FFI_IMPL").is_ok() {
        println!("cargo:rustc-cfg=no_binius_prover");
        return;
    }
    
    // Try to find the closed-source library via environment variable
    if let Ok(path) = env::var("BINIUS_PROVER_LIB_PATH") {
        let path = PathBuf::from(path);
        
        if verify_library_exists(&path) {
            // Set up linking
            println!("cargo:rustc-link-search={}", path.display());
            println!("cargo:rustc-link-lib=binius_prover");
            
            // Store the library info for runtime access
            println!("cargo:rustc-env=LINKED_BINIUS_LIB_PATH={}", path.display());
            if let Some(file_name) = find_library_file(&path) {
                println!("cargo:rustc-env=LINKED_BINIUS_LIB_NAME={}", file_name);
            }
            
            // Set a cfg flag to enable integration tests
            println!("cargo:rustc-cfg=has_binius_prover");
        } else {
            println!("cargo:rustc-cfg=no_binius_prover");
        }
    } else {
        // Library not found - this is OK for development
        println!("cargo:rustc-cfg=no_binius_prover");
    }
    
    // Always rerun if these change
    println!("cargo:rerun-if-env-changed=BINIUS_PROVER_LIB_PATH");
    println!("cargo:rerun-if-changed=build.rs");
}

fn find_library_file(dir: &Path) -> Option<String> {
    let lib_names = [
        "libbinius_prover.so",      // Linux dynamic
        "libbinius_prover.dylib",   // macOS dynamic
        "binius_prover.dll",        // Windows dynamic
        "libbinius_prover.a",       // Static library
    ];
    
    for name in &lib_names {
        if dir.join(name).exists() {
            return Some(name.to_string());
        }
    }
    None
}

fn verify_library_exists(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    
    // Check for different library naming conventions
    let lib_names = [
        "libbinius_prover.so",      // Linux
        "libbinius_prover.dylib",   // macOS
        "binius_prover.dll",        // Windows
        "libbinius_prover.a",       // Static library
    ];
    
    for name in &lib_names {
        if dir.join(name).exists() {
            return true;
        }
    }
    
    false
}