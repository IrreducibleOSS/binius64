//! Optimization configuration

/// Configuration for enabling/disabling specific optimizations
#[derive(Clone, Debug)]
pub struct OptConfig {
    // Expression rewriting optimizations
    pub xor_self_elimination: bool,        // x ⊕ x → 0
    pub xor_zero_elimination: bool,        // x ⊕ 0 → x
    pub xor_ones_elimination: bool,        // x ⊕ 1* → ~x
    pub and_zero_elimination: bool,        // x & 0 → 0
    pub and_ones_elimination: bool,        // x & 0xFF... → x
    pub and_self_elimination: bool,        // x & x → x
    pub or_zero_elimination: bool,         // x | 0 → x
    pub or_ones_elimination: bool,         // x | 1* → 1*
    pub or_self_elimination: bool,         // x | x → x
    pub not_const_elimination: bool,       // ~0 → 1*, ~1* → 0
    pub double_not_elimination: bool,      // ~~x → x
    pub xor_term_cancellation: bool,       // (a⊕b)⊕(a⊕c) → b⊕c
    
    // Complex pattern rewrites
    pub xor_of_ands_rewrite: bool,         // XOR of AND terms: (a&b)⊕(a&c)⊕(b&c) → optimized
    pub conditional_select_rewrite: bool,  // Conditional select: (a&b)⊕((~a)&c) → a&(b⊕c)⊕c
    
    // Multi-constraint templates
    pub carry_chain_fusion: bool,          // Multiple adds → single carry
    
    // Common subexpression elimination
    pub cse_enabled: bool,                 // Detect and reuse common subexpressions
    
    // Canonicalization
    pub canonicalize_enabled: bool,        // Enable expression canonicalization
}

impl Default for OptConfig {
    fn default() -> Self {
        let mut config = Self::all_enabled();  // All optimizations on by default
        config.cse_enabled = false;  // CSE disabled by default
        config.canonicalize_enabled = false;  // Canonicalization disabled by default
        config
    }
}

impl OptConfig {
    /// Create config with all optimizations enabled
    pub fn all_enabled() -> Self {
        Self {
            xor_self_elimination: true,
            xor_zero_elimination: true,
            xor_ones_elimination: true,
            and_zero_elimination: true,
            and_ones_elimination: true,
            and_self_elimination: true,
            or_zero_elimination: true,
            or_ones_elimination: true,
            or_self_elimination: true,
            not_const_elimination: true,
            double_not_elimination: true,
            xor_term_cancellation: true,
            xor_of_ands_rewrite: true,
            conditional_select_rewrite: true,
            carry_chain_fusion: true,
            cse_enabled: true,
            canonicalize_enabled: true,
        }
    }
    
    /// Create config with no optimizations enabled
    pub fn none_enabled() -> Self {
        Self {
            xor_self_elimination: false,
            xor_zero_elimination: false,
            xor_ones_elimination: false,
            and_zero_elimination: false,
            and_ones_elimination: false,
            and_self_elimination: false,
            or_zero_elimination: false,
            or_ones_elimination: false,
            or_self_elimination: false,
            not_const_elimination: false,
            double_not_elimination: false,
            xor_term_cancellation: false,
            xor_of_ands_rewrite: false,
            conditional_select_rewrite: false,
            carry_chain_fusion: false,
            cse_enabled: false,
            canonicalize_enabled: false,
        }
    }
    
    /// Check if any rewriting optimizations are enabled
    pub fn has_any_rewriting(&self) -> bool {
        self.xor_self_elimination ||
        self.xor_zero_elimination ||
        self.xor_ones_elimination ||
        self.and_zero_elimination ||
        self.and_ones_elimination ||
        self.and_self_elimination ||
        self.or_zero_elimination ||
        self.or_ones_elimination ||
        self.or_self_elimination ||
        self.not_const_elimination ||
        self.double_not_elimination ||
        self.xor_term_cancellation ||
        self.xor_of_ands_rewrite ||
        self.conditional_select_rewrite
    }
    
    /// Check if any template optimizations are enabled
    pub fn has_any_templates(&self) -> bool {
        self.carry_chain_fusion
    }
}