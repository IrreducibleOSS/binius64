//! Configuration for controlling optimizations

use std::env;

/// Configuration for enabling/disabling specific optimizations
#[derive(Debug, Clone)]
pub struct OptimizationConfig {
    // Expression-level optimizations (in rules.rs)
    /// XOR chain consolidation: (a ⊕ b) ⊕ (a ⊕ c) → b ⊕ c
    pub xor_chain_consolidation: bool,
    
    /// XOR self-cancellation: x ⊕ x → 0
    pub xor_self_cancellation: bool,
    
    /// XOR with zero identity: x ⊕ 0 → x
    pub xor_with_zero: bool,
    
    /// XOR with all-ones: x ⊕ 1* → ¬x
    pub xor_with_ones: bool,
    
    /// Double NOT elimination: ¬¬x → x
    pub double_not_elimination: bool,
    
    /// NOT constant folding: ¬0 → 1*, ¬1* → 0
    pub not_constant_folding: bool,
    
    /// AND self-identity: x ∧ x → x
    pub and_self_identity: bool,
    
    /// AND with zero: x ∧ 0 → 0
    pub and_with_zero: bool,
    
    /// AND with all-ones identity: x ∧ 1* → x
    pub and_with_ones: bool,
    
    /// OR self-identity: x ∨ x → x
    pub or_self_identity: bool,
    
    /// OR with zero identity: x ∨ 0 → x
    pub or_with_zero: bool,
    
    /// OR with all-ones: x ∨ 1* → 1*
    pub or_with_ones: bool,
    
    // Constraint-level optimizations
    /// Masked AND-XOR fusion: a ⊕ ((¬b) ∧ c) → single constraint
    pub masked_and_xor_fusion: bool,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        // All optimizations enabled by default
        Self {
            xor_chain_consolidation: true,
            xor_self_cancellation: true,
            xor_with_zero: true,
            xor_with_ones: true,
            double_not_elimination: true,
            not_constant_folding: true,
            and_self_identity: true,
            and_with_zero: true,
            and_with_ones: true,
            or_self_identity: true,
            or_with_zero: true,
            or_with_ones: true,
            masked_and_xor_fusion: true,
        }
    }
}

impl OptimizationConfig {
    /// Create a config with all optimizations disabled
    pub fn all_disabled() -> Self {
        Self {
            xor_chain_consolidation: false,
            xor_self_cancellation: false,
            xor_with_zero: false,
            xor_with_ones: false,
            double_not_elimination: false,
            not_constant_folding: false,
            and_self_identity: false,
            and_with_zero: false,
            and_with_ones: false,
            or_self_identity: false,
            or_with_zero: false,
            or_with_ones: false,
            masked_and_xor_fusion: false,
        }
    }
    
    /// Parse configuration from command-line arguments
    pub fn from_args() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut config = Self::default();
        
        for arg in &args[1..] {  // Skip program name
            match arg.as_str() {
                "--no-opt" => return Self::all_disabled(),
                "--no-xor-chain" => config.xor_chain_consolidation = false,
                "--no-xor-self" => config.xor_self_cancellation = false,
                "--no-xor-zero" => config.xor_with_zero = false,
                "--no-xor-ones" => config.xor_with_ones = false,
                "--no-double-not" => config.double_not_elimination = false,
                "--no-not-const" => config.not_constant_folding = false,
                "--no-and-self" => config.and_self_identity = false,
                "--no-and-zero" => config.and_with_zero = false,
                "--no-and-ones" => config.and_with_ones = false,
                "--no-or-self" => config.or_self_identity = false,
                "--no-or-zero" => config.or_with_zero = false,
                "--no-or-ones" => config.or_with_ones = false,
                "--no-masked-and-xor" => config.masked_and_xor_fusion = false,
                "--help" => {
                    Self::print_help();
                    std::process::exit(0);
                }
                _ if arg.starts_with("--no-") => {
                    eprintln!("Unknown optimization flag: {}", arg);
                    Self::print_help();
                    std::process::exit(1);
                }
                _ => {} // Ignore non-flag arguments
            }
        }
        
        config
    }
    
    /// Print help message showing all available flags
    fn print_help() {
        println!("Beamish Optimization Flags:");
        println!();
        println!("Global:");
        println!("  --no-opt              Disable all optimizations");
        println!();
        println!("XOR optimizations:");
        println!("  --no-xor-self         Disable XOR self-cancellation");
        println!("  --no-xor-zero         Disable XOR with zero identity");
        println!("  --no-xor-ones         Disable XOR with all-ones");
        println!();
        println!("NOT optimizations:");
        println!("  --no-double-not       Disable double NOT elimination");
        println!("  --no-not-const        Disable NOT constant folding");
        println!();
        println!("AND optimizations:");
        println!("  --no-and-self         Disable AND self-identity");
        println!("  --no-and-zero         Disable AND with zero");
        println!("  --no-and-ones         Disable AND with all-ones identity");
        println!();
        println!("OR optimizations:");
        println!("  --no-or-self          Disable OR self-identity");
        println!("  --no-or-zero          Disable OR with zero identity");
        println!("  --no-or-ones          Disable OR with all-ones");
        println!();
        println!("Pattern optimizations:");
        println!("  --no-xor-chain        Disable XOR chain consolidation");
        println!("  --no-masked-and-xor   Disable Masked AND-XOR fusion");
        println!();
        println!("Native Forms:");
        println!("  [rotation-xor]        Rotation-XOR: (x>>>a) ⊕ (x>>>b) → single operand");
        println!("  [xor-operands]        XOR operands: a ⊕ b ⊕ c → single operand");
        println!("  [constant-operands]   Constant operands: x & 0xFF → direct operand");
        println!();
        println!("  --help                Show this help message");
    }
    
    /// Print current optimization status
    pub fn print_status(&self) {
        println!("Optimization settings:");
        println!("  XOR chain consolidation: {}", if self.xor_chain_consolidation { "✓" } else { "✗" });
        println!("  XOR self-cancellation:   {}", if self.xor_self_cancellation { "✓" } else { "✗" });
        println!("  XOR with zero:           {}", if self.xor_with_zero { "✓" } else { "✗" });
        println!("  XOR with all-ones:       {}", if self.xor_with_ones { "✓" } else { "✗" });
        println!("  Double NOT elimination:  {}", if self.double_not_elimination { "✓" } else { "✗" });
        println!("  NOT constant folding:    {}", if self.not_constant_folding { "✓" } else { "✗" });
        println!("  AND self-identity:       {}", if self.and_self_identity { "✓" } else { "✗" });
        println!("  AND with zero:           {}", if self.and_with_zero { "✓" } else { "✗" });
        println!("  AND with all-ones:       {}", if self.and_with_ones { "✓" } else { "✗" });
        println!("  OR self-identity:        {}", if self.or_self_identity { "✓" } else { "✗" });
        println!("  OR with zero:            {}", if self.or_with_zero { "✓" } else { "✗" });
        println!("  OR with all-ones:        {}", if self.or_with_ones { "✓" } else { "✗" });
        println!("  Masked AND-XOR fusion:   {}", if self.masked_and_xor_fusion { "✓" } else { "✗" });
    }
}