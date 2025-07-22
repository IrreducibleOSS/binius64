use std::collections::BTreeMap;
use regex::Regex;

// Include build-time generated constants
include!(concat!(env!("OUT_DIR"), "/platform_build_info.rs"));

pub struct PlatformDiagnostics {
    hardware: HardwareInfo,
    os_runtime: OSRuntimeInfo,
    llvm_config: LLVMConfig,
    _rust_compiler: RustCompilerInfo,
    code_features: CodeFeatures,
    codebase_usage: CodebaseUsage,
}

#[derive(Debug)]
struct HardwareInfo {
    cpu_model: String,
    architecture: &'static str,
    vendor: String,
    core_count: usize,
}

#[derive(Debug)]
struct OSRuntimeInfo {
    os: &'static str,
    kernel_version: String,
    runtime_features: BTreeMap<&'static str, bool>,
}

#[derive(Debug)]
struct LLVMConfig {
    target_triple: String,
    target_cpu: String,
    enabled_features: Vec<String>,
}

#[derive(Debug)]
struct RustCompilerInfo {
    rustc_version: String,
    rustflags: String,
    _cfg_flags: BTreeMap<String, String>,
}

#[derive(Debug)]
struct CodeFeatures {
    compile_time_features: Vec<String>,
    runtime_detected_features: BTreeMap<&'static str, bool>,
}

#[derive(Debug)]
struct CodebaseUsage {
    cfg_features: BTreeMap<String, Vec<String>>, // feature -> files using it
    runtime_detections: BTreeMap<String, Vec<String>>, // feature -> files using runtime detection
    arch_modules: Vec<String>, // architecture-specific modules found
}

// ANSI color codes
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

impl PlatformDiagnostics {
    pub fn gather() -> Self {
        Self {
            hardware: Self::detect_hardware(),
            os_runtime: Self::detect_os_runtime(),
            llvm_config: Self::parse_llvm_config(),
            _rust_compiler: Self::get_rust_compiler_info(),
            code_features: Self::analyze_code_features(),
            codebase_usage: Self::scan_codebase_usage(),
        }
    }

    fn detect_hardware() -> HardwareInfo {
        let cpu_model = Self::get_cpu_model();
        let vendor = Self::detect_vendor(&cpu_model);
        let core_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        
        HardwareInfo {
            cpu_model,
            architecture: std::env::consts::ARCH,
            vendor,
            core_count,
        }
    }

    fn detect_vendor(cpu_model: &str) -> String {
        let model_lower = cpu_model.to_lowercase();
        if model_lower.contains("apple") {
            "Apple".to_string()
        } else if model_lower.contains("graviton") {
            "AWS".to_string()
        } else if model_lower.contains("ampere") {
            "Ampere".to_string()
        } else if model_lower.contains("intel") {
            "Intel".to_string()
        } else if model_lower.contains("amd") {
            "AMD".to_string()
        } else {
            "Generic".to_string()
        }
    }

    fn get_cpu_model() -> String {
        #[cfg(target_os = "linux")]
        {
            if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
                // For x86_64
                if let Some(line) = cpuinfo.lines().find(|l| l.starts_with("model name")) {
                    return line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
                // For ARM
                if let Some(line) = cpuinfo.lines().find(|l| l.starts_with("CPU implementer")) {
                    let implementer = line.split(':').nth(1).unwrap_or("").trim();
                    if let Some(part_line) = cpuinfo.lines().find(|l| l.starts_with("CPU part")) {
                        let part = part_line.split(':').nth(1).unwrap_or("").trim();
                        return format!("ARM implementer {} part {}", implementer, part);
                    }
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("sysctl")
                .arg("-n")
                .arg("machdep.cpu.brand_string")
                .output()
            {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
        
        "Unknown CPU".to_string()
    }

    fn detect_os_runtime() -> OSRuntimeInfo {
        let mut runtime_features = BTreeMap::new();
        
        #[cfg(target_arch = "aarch64")]
        {
            use std::arch::is_aarch64_feature_detected;
            
            runtime_features.insert("neon", is_aarch64_feature_detected!("neon"));
            runtime_features.insert("aes", is_aarch64_feature_detected!("aes"));
            runtime_features.insert("sha2", is_aarch64_feature_detected!("sha2"));
            runtime_features.insert("sha3", is_aarch64_feature_detected!("sha3"));
            runtime_features.insert("crc", is_aarch64_feature_detected!("crc"));
            runtime_features.insert("lse", is_aarch64_feature_detected!("lse"));
            runtime_features.insert("dotprod", is_aarch64_feature_detected!("dotprod"));
            runtime_features.insert("fp16", is_aarch64_feature_detected!("fp16"));
            runtime_features.insert("sve", is_aarch64_feature_detected!("sve"));
            runtime_features.insert("sve2", is_aarch64_feature_detected!("sve2"));
            runtime_features.insert("fcma", is_aarch64_feature_detected!("fcma"));
            runtime_features.insert("rcpc", is_aarch64_feature_detected!("rcpc"));
            runtime_features.insert("rcpc2", is_aarch64_feature_detected!("rcpc2"));
            runtime_features.insert("dpb", is_aarch64_feature_detected!("dpb"));
            runtime_features.insert("dpb2", is_aarch64_feature_detected!("dpb2"));
            runtime_features.insert("bf16", is_aarch64_feature_detected!("bf16"));
            runtime_features.insert("i8mm", is_aarch64_feature_detected!("i8mm"));
            runtime_features.insert("f32mm", is_aarch64_feature_detected!("f32mm"));
            runtime_features.insert("f64mm", is_aarch64_feature_detected!("f64mm"));
        }
        
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::is_x86_feature_detected;
            
            runtime_features.insert("avx", is_x86_feature_detected!("avx"));
            runtime_features.insert("avx2", is_x86_feature_detected!("avx2"));
            runtime_features.insert("avx512f", is_x86_feature_detected!("avx512f"));
            runtime_features.insert("gfni", is_x86_feature_detected!("gfni"));
            runtime_features.insert("aes", is_x86_feature_detected!("aes"));
            runtime_features.insert("pclmulqdq", is_x86_feature_detected!("pclmulqdq"));
            runtime_features.insert("sha", is_x86_feature_detected!("sha"));
            runtime_features.insert("vaes", is_x86_feature_detected!("vaes"));
            runtime_features.insert("vpclmulqdq", is_x86_feature_detected!("vpclmulqdq"));
        }
        
        let kernel_version = Self::get_kernel_version();
        
        OSRuntimeInfo {
            os: std::env::consts::OS,
            kernel_version,
            runtime_features,
        }
    }

    fn get_kernel_version() -> String {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/version")
                .ok()
                .and_then(|s| s.split_whitespace().nth(2).map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown".to_string())
        }
        
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("uname")
                .arg("-r")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            "unknown".to_string()
        }
    }

    fn parse_llvm_config() -> LLVMConfig {
        // Parse target-cpu from RUSTFLAGS
        // Handles both "-C target-cpu=native" and "-Ctarget-cpu=native" formats
        let mut target_cpu = "generic".to_string();
        
        // Try to find target-cpu in RUSTFLAGS
        for (i, part) in BUILD_RUSTFLAGS.split_whitespace().enumerate() {
            if part == "-C" {
                // Check next part for "target-cpu=value"
                if let Some(next) = BUILD_RUSTFLAGS.split_whitespace().nth(i + 1) {
                    if let Some(cpu) = next.strip_prefix("target-cpu=") {
                        target_cpu = cpu.to_string();
                        break;
                    }
                }
            } else if let Some(rest) = part.strip_prefix("-C") {
                // Handle "-Ctarget-cpu=value" (no space)
                if let Some(cpu) = rest.strip_prefix("target-cpu=") {
                    target_cpu = cpu.to_string();
                    break;
                }
            }
        }

        let enabled_features = COMPILE_TIME_FEATURES
            .iter()
            .map(|s| s.to_string())
            .collect();

        LLVMConfig {
            target_triple: BUILD_TARGET.to_string(),
            target_cpu,
            enabled_features,
        }
    }

    fn get_rust_compiler_info() -> RustCompilerInfo {
        let mut cfg_flags = BTreeMap::new();
        
        for (key, value) in CFG_VARIABLES {
            if let Some(cfg_name) = key.strip_prefix("CARGO_CFG_") {
                cfg_flags.insert(cfg_name.to_lowercase(), value.to_string());
            }
        }
        
        RustCompilerInfo {
            rustc_version: std::env::var("RUSTC_VERSION")
                .unwrap_or_else(|_| {
                    // Try to get version at runtime
                    std::process::Command::new("rustc")
                        .arg("--version")
                        .output()
                        .ok()
                        .and_then(|output| String::from_utf8(output.stdout).ok())
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                }),
            rustflags: BUILD_RUSTFLAGS.to_string(),
            _cfg_flags: cfg_flags,
        }
    }

    fn analyze_code_features() -> CodeFeatures {
        let compile_time_features = COMPILE_TIME_FEATURES
            .iter()
            .map(|s| s.to_string())
            .collect();
            
        let runtime_detected_features = Self::detect_os_runtime().runtime_features;
        
        CodeFeatures {
            compile_time_features,
            runtime_detected_features,
        }
    }
    
    fn scan_codebase_usage() -> CodebaseUsage {
        let mut cfg_features = BTreeMap::new();
        let mut runtime_detections = BTreeMap::new();
        let mut arch_modules = Vec::new();
        
        // Try to find the workspace root
        let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .and_then(|dir| {
                let path = std::path::Path::new(&dir);
                // Walk up to find workspace root (has Cargo.toml with [workspace])
                let mut current = Some(path);
                while let Some(p) = current {
                    let cargo_toml = p.join("Cargo.toml");
                    if cargo_toml.exists() {
                        if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                            if content.contains("[workspace]") {
                                return p.to_str().map(|s| s.to_string());
                            }
                        }
                    }
                    current = p.parent();
                }
                None
            });
            
        if let Some(root) = workspace_root {
            // Compile regexes once for efficiency
            // This regex finds all target_feature = "..." patterns, even multiple in one cfg
            let cfg_regex = Regex::new(r#"target_feature\s*=\s*"([^"]+)""#).unwrap();
            let detect_regex = Regex::new(r#"is_\w+_feature_detected!\s*\(\s*"([^"]+)"\s*\)"#).unwrap();
            
            // Scan for arch modules and features
            Self::scan_directory_with_regex(
                &std::path::Path::new(&root),
                &mut cfg_features,
                &mut runtime_detections,
                &mut arch_modules,
                &root,
                &cfg_regex,
                &detect_regex,
            );
            
            arch_modules.sort();
            arch_modules.dedup();
        }
        
        CodebaseUsage {
            cfg_features,
            runtime_detections,
            arch_modules,
        }
    }
    
    fn scan_directory_with_regex(
        dir: &std::path::Path,
        cfg_features: &mut BTreeMap<String, Vec<String>>,
        runtime_detections: &mut BTreeMap<String, Vec<String>>,
        arch_modules: &mut Vec<String>,
        root: &str,
        cfg_regex: &Regex,
        detect_regex: &Regex,
    ) {
        
        // Skip common non-source directories
        if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
            if name == "target" || name == ".git" || name == "node_modules" || name.starts_with('.') {
                return;
            }
        }
        
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                
                if path.is_dir() {
                    // Check if this is an arch module
                    if path.file_name() == Some(std::ffi::OsStr::new("arch")) {
                        // List subdirectories as arch modules
                        if let Ok(arch_entries) = std::fs::read_dir(&path) {
                            for arch_entry in arch_entries.filter_map(|e| e.ok()) {
                                if arch_entry.path().is_dir() {
                                    if let Some(name) = arch_entry.file_name().to_str() {
                                        arch_modules.push(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                    
                    // Recurse into subdirectory
                    Self::scan_directory_with_regex(&path, cfg_features, runtime_detections, arch_modules, root, cfg_regex, detect_regex);
                } else if path.extension() == Some(std::ffi::OsStr::new("rs")) {
                    // Scan Rust file for features
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let relative_path = path.strip_prefix(root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .to_string();
                        
                        // Find all cfg features
                        for cap in cfg_regex.captures_iter(&content) {
                            if let Some(feature_match) = cap.get(1) {
                                let feature = feature_match.as_str();
                                // Skip invalid feature names
                                if !feature.is_empty() && !feature.contains('.') {
                                    cfg_features
                                        .entry(feature.to_string())
                                        .or_insert_with(Vec::new)
                                        .push(relative_path.clone());
                                }
                            }
                        }
                        
                        // Find all runtime detections
                        for cap in detect_regex.captures_iter(&content) {
                            if let Some(feature_match) = cap.get(1) {
                                let feature = feature_match.as_str();
                                // Skip invalid feature names and generic placeholders
                                if !feature.is_empty() && !feature.contains('.') && feature != "feature" {
                                    runtime_detections
                                        .entry(feature.to_string())
                                        .or_insert_with(Vec::new)
                                        .push(relative_path.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    pub fn print(&self) {
        println!("\n{BOLD}Platform Feature Report{RESET}\n");
        
        // 1. Hardware
        self.print_hardware_compact();
        println!();
        
        // 2. OS/Runtime
        self.print_os_runtime_compact();
        println!();
        
        // 3. Compilation Target (LLVM)
        self.print_llvm_compact();
        println!();
        
        // 4. Available CPU Instructions
        self.print_rust_compiler_compact();
        println!();
        
        // 5. Codebase Usage
        self.print_codebase_usage_compact();
    }


    fn print_hardware_compact(&self) {
        println!("{BOLD}{CYAN}Hardware:{RESET} {} {} ({} cores)", 
            self.hardware.vendor, self.hardware.architecture, self.hardware.core_count);
        println!("{CYAN}CPU:{RESET} {}", self.hardware.cpu_model);
        
        match self.hardware.vendor.as_str() {
            "Apple" => {
                println!("{CYAN}Features:{RESET} {GREEN}✓{RESET}AMX, {GREEN}✓{RESET}Neural Engine, {GREEN}✓{RESET}P+E cores, {RED}✗{RESET}SVE/SVE2, {GREEN}✓{RESET}NEON");
            }
            "AWS" => {
                println!("{CYAN}Features:{RESET} {GREEN}✓{RESET}SVE-256bit, {GREEN}✓{RESET}Server memory, {GREEN}✓{RESET}Large cache, {RED}✗{RESET}AMX, {GREEN}✓{RESET}NEON");
            }
            _ => {
                println!("{CYAN}Features:{RESET} {YELLOW}?{RESET}Vendor-specific, {GREEN}✓{RESET}NEON, {YELLOW}?{RESET}Crypto");
            }
        }
        println!("  {DIM}↓ CPU capabilities exposed to OS{RESET}");
    }

    fn print_os_runtime_compact(&self) {
        println!("{BOLD}{CYAN}OS/Runtime:{RESET} {} (kernel {})", self.os_runtime.os, self.os_runtime.kernel_version);
        
        // Group features by status
        let detected: Vec<&str> = self.os_runtime.runtime_features.iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| *k)
            .collect();
        let not_found: Vec<&str> = self.os_runtime.runtime_features.iter()
            .filter(|(_, v)| !**v)
            .map(|(k, _)| *k)
            .collect();
        
        if !detected.is_empty() {
            println!("{GREEN}Detected:{RESET} {}", detected.join(", "));
        }
        if !not_found.is_empty() {
            println!("{DIM}Not available:{RESET} {}", not_found.join(", "));
        }
        println!("  {DIM}↓ Features available to LLVM{RESET}");
    }

    fn print_llvm_compact(&self) {
        println!("{BOLD}{CYAN}Compilation Target:{RESET}");
        println!("{CYAN}Triple:{RESET} {}", self.llvm_config.target_triple);
        println!("{CYAN}CPU:{RESET} {}", self.llvm_config.target_cpu);
        
        match self.llvm_config.target_cpu.as_str() {
            "native" => {
                println!("{CYAN}Strategy:{RESET} {YELLOW}Native{RESET} - Optimized for this specific CPU");
                println!("{DIM}         Binary only runs on CPUs with same features{RESET}");
            }
            "generic" => {
                println!("{CYAN}Strategy:{RESET} {GREEN}Generic{RESET} - Portable across all {} CPUs", 
                    if self.llvm_config.target_triple.contains("aarch64") { "ARM64" } 
                    else if self.llvm_config.target_triple.contains("x86_64") { "x86-64" } 
                    else { "target" });
                println!("{DIM}         Uses explicit features but no CPU-specific scheduling{RESET}");
            }
            cpu if cpu.starts_with("apple-") => {
                println!("{CYAN}Strategy:{RESET} {MAGENTA}Apple Silicon{RESET} - Optimized for {}", cpu);
                println!("{DIM}         Enables AMX, disables SVE{RESET}");
            }
            cpu if cpu.contains("neoverse") => {
                println!("{CYAN}Strategy:{RESET} {BLUE}Server ARM{RESET} - Optimized for {}", cpu);
                println!("{DIM}         Enables SVE, optimized for cloud workloads{RESET}");
            }
            _ => {
                println!("{CYAN}Strategy:{RESET} Custom CPU target");
            }
        }
        println!("  {DIM}↓ Code generation configured{RESET}");
    }

    fn print_rust_compiler_compact(&self) {
        println!("{BOLD}{CYAN}Available CPU Instructions:{RESET}");
        
        // Group features by category
        let mut simd_features = Vec::new();
        let mut crypto_features = Vec::new();
        let mut arch_features = Vec::new();
        
        for feature in &self.code_features.compile_time_features {
            if ["neon", "sve", "sve2", "dotprod", "fp16", "bf16", "i8mm", "f32mm", "f64mm", "fcma"].contains(&feature.as_str()) {
                simd_features.push(feature.as_str());
            } else if ["aes", "sha2", "sha3", "crc", "pmuv3"].contains(&feature.as_str()) {
                crypto_features.push(feature.as_str());
            } else if !feature.starts_with("v8.") && feature != "vh" {
                arch_features.push(feature.as_str());
            }
        }
        
        println!("{CYAN}Total:{RESET} {} CPU features available to compiler", self.code_features.compile_time_features.len());
        
        if !simd_features.is_empty() {
            simd_features.sort();
            println!("  {GREEN}SIMD:{RESET} {}", simd_features.join(", "));
        }
        if !crypto_features.is_empty() {
            crypto_features.sort();
            println!("  {GREEN}Crypto:{RESET} {}", crypto_features.join(", "));
        }
        if !arch_features.is_empty() {
            arch_features.sort();
            // Always show the features, but wrap if too many
            if arch_features.len() <= 6 {
                println!("  {GREEN}Other:{RESET} {}", arch_features.join(", "));
            } else {
                // Show in multiple lines for readability
                println!("  {GREEN}Other:{RESET}");
                for chunk in arch_features.chunks(8) {
                    println!("    {}", chunk.join(", "));
                }
            }
        }
        
        // Show important missing features
        #[cfg(target_arch = "aarch64")]
        {
            let important_missing = vec!["sve", "sve2"]
                .into_iter()
                .filter(|f| !self.code_features.compile_time_features.contains(&f.to_string()))
                .collect::<Vec<_>>();
            if !important_missing.is_empty() {
                println!("  {DIM}Not available:{RESET} {} (code paths requiring these are excluded)", important_missing.join(", "));
            }
        }
        
        println!("  {DIM}↓ Compiler uses these to select optimized code paths{RESET}");
    }


    fn print_codebase_usage_compact(&self) {
        // Always show the codebase section header
        println!("{BOLD}{CYAN}Codebase Analysis:{RESET}");
        
        if self.codebase_usage.cfg_features.is_empty() && 
           self.codebase_usage.runtime_detections.is_empty() && 
           self.codebase_usage.arch_modules.is_empty() {
            println!("{DIM}  No feature usage detected{RESET}");
            return;
        }
        
        
        // Show arch modules first
        if !self.codebase_usage.arch_modules.is_empty() {
            println!("{MAGENTA}Arch modules:{RESET} {}", self.codebase_usage.arch_modules.join(", "));
        }
        
        if !self.codebase_usage.cfg_features.is_empty() {
            // Check which used features are enabled vs disabled
            let mut enabled_used = Vec::new();
            let mut disabled_used = Vec::new();
            
            for (feature, locations) in &self.codebase_usage.cfg_features {
                // Categorize features by architecture
                let is_arm_feature = ["neon", "sve", "sve2", "aes", "sha2", "sha3", "crc", "lse", 
                                     "dotprod", "fp16", "bf16", "i8mm", "f32mm", "f64mm", "fcma",
                                     "rcpc", "rcpc2", "dpb", "dpb2"].contains(&feature.as_str());
                let is_x86_feature = ["avx", "avx2", "avx512f", "gfni", "sse", "sse2", "sse3", 
                                     "ssse3", "sse4.1", "sse4.2", "pclmulqdq", "vpclmulqdq",
                                     "vaes", "aes", "sha"].contains(&feature.as_str());
                let is_wasm_feature = ["atomics", "simd128"].contains(&feature.as_str());
                
                // Skip features for other architectures
                #[cfg(target_arch = "aarch64")]
                if is_x86_feature && !is_arm_feature {
                    continue;
                }
                
                #[cfg(target_arch = "x86_64")]
                if is_arm_feature && !is_x86_feature {
                    continue;
                }
                
                #[cfg(target_arch = "wasm32")]
                if !is_wasm_feature {
                    continue;
                }
                
                #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "wasm32")))]
                if is_arm_feature || is_x86_feature || is_wasm_feature {
                    continue;
                }
                
                if self.code_features.compile_time_features.contains(feature) {
                    enabled_used.push(feature.clone());
                } else {
                    disabled_used.push(feature.clone());
                }
            }
            
            if !enabled_used.is_empty() {
                println!("{GREEN}Used & Enabled:{RESET}");
                for feature in &enabled_used {
                    if let Some(locations) = self.codebase_usage.cfg_features.get(feature) {
                        // Group files by directory
                        let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
                        for loc in locations {
                            if let Some(slash_pos) = loc.rfind('/') {
                                let dir = loc[..slash_pos].to_string();
                                let file = loc[slash_pos + 1..].to_string();
                                let files = by_dir.entry(dir).or_insert_with(Vec::new);
                                if !files.contains(&file) {
                                    files.push(file);
                                }
                            } else {
                                let files = by_dir.entry(String::new()).or_insert_with(Vec::new);
                                if !files.contains(loc) {
                                    files.push(loc.clone());
                                }
                            }
                        }
                        
                        println!("  {GREEN}{}:{RESET}", feature);
                        let mut shown = 0;
                        let mut dir_count = 0;
                        for (dir, files) in by_dir.iter() {
                            if dir_count >= 5 && by_dir.len() > 5 {
                                println!("    ... in {} more files", locations.len() - shown);
                                break;
                            }
                            dir_count += 1;
                            
                            if files.len() == 1 {
                                println!("    {}/{}", dir, files[0]);
                                shown += 1;
                            } else if files.len() <= 10 {
                                // List all files if 10 or fewer
                                println!("    {}/: {}", dir, files.join(", "));
                                shown += files.len();
                            } else {
                                // Show first 10 files and indicate there are more
                                let first_10: Vec<_> = files.iter().take(10).cloned().collect();
                                println!("    {}/: {} (and {} more)", dir, first_10.join(", "), files.len() - 10);
                                shown += files.len();
                            }
                        }
                    }
                }
            }
            
            if !disabled_used.is_empty() {
                println!("{RED}⚠ Used but NOT Enabled:{RESET}");
                for feature in &disabled_used {
                    if let Some(locations) = self.codebase_usage.cfg_features.get(feature) {
                        // Group files by directory
                        let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
                        for loc in locations {
                            if let Some(slash_pos) = loc.rfind('/') {
                                let dir = loc[..slash_pos].to_string();
                                let file = loc[slash_pos + 1..].to_string();
                                let files = by_dir.entry(dir).or_insert_with(Vec::new);
                                if !files.contains(&file) {
                                    files.push(file);
                                }
                            } else {
                                let files = by_dir.entry(String::new()).or_insert_with(Vec::new);
                                if !files.contains(loc) {
                                    files.push(loc.clone());
                                }
                            }
                        }
                        
                        println!("  {RED}{}:{RESET}", feature);
                        let mut shown = 0;
                        let mut dir_count = 0;
                        for (dir, files) in by_dir.iter() {
                            if dir_count >= 5 && by_dir.len() > 5 {
                                println!("    ... in {} more files", locations.len() - shown);
                                break;
                            }
                            dir_count += 1;
                            
                            if files.len() == 1 {
                                println!("    {}/{}", dir, files[0]);
                                shown += 1;
                            } else if files.len() <= 10 {
                                // List all files if 10 or fewer
                                println!("    {}/: {}", dir, files.join(", "));
                                shown += files.len();
                            } else {
                                // Show first 10 files and indicate there are more
                                let first_10: Vec<_> = files.iter().take(10).cloned().collect();
                                println!("    {}/: {} (and {} more)", dir, first_10.join(", "), files.len() - 10);
                                shown += files.len();
                            }
                        }
                    }
                }
            }
        }
        
        if !self.codebase_usage.runtime_detections.is_empty() {
            let detections: Vec<String> = self.codebase_usage.runtime_detections.keys().cloned().collect();
            println!("{BLUE}Runtime detections:{RESET} {}", detections.join(", "));
        }
    }

    pub fn get_summary(&self) -> PlatformSummary {
        let has_mismatches = self.code_features.compile_time_features.iter()
            .any(|f| self.code_features.runtime_detected_features.get(f.as_str()) == Some(&false));
            
        PlatformSummary {
            platform: format!("{} on {}", self.hardware.vendor, self.hardware.architecture),
            cpu: self.hardware.cpu_model.clone(),
            target: self.llvm_config.target_triple.clone(),
            target_cpu: self.llvm_config.target_cpu.clone(),
            has_feature_mismatches: has_mismatches,
        }
    }
}

pub struct PlatformSummary {
    pub platform: String,
    pub cpu: String,
    pub target: String,
    pub target_cpu: String,
    pub has_feature_mismatches: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_platform_diagnostics() {
        let diag = PlatformDiagnostics::gather();
        diag.print();
        
        // Also test the summary
        let summary = diag.get_summary();
        assert!(!summary.platform.is_empty());
        assert!(!summary.cpu.is_empty());
        assert!(!summary.target.is_empty());
    }
}