// config.rs - Configuration for the prover

/// Configuration for the prover
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProverConfig {
    num_threads: usize,
    tower_level: u8,
    security_bits: u32,
}

impl ProverConfig {
    /// Create a new builder for ProverConfig
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Get the number of threads (0 means auto-detect)
    pub fn num_threads(&self) -> usize {
        self.num_threads
    }

    /// Get the tower level (0-7)
    pub fn tower_level(&self) -> u8 {
        self.tower_level
    }

    /// Get the security bits
    pub fn security_bits(&self) -> u32 {
        self.security_bits
    }
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            num_threads: 0, // 0 means auto-detect
            tower_level: 7,
            security_bits: 128,
        }
    }
}

/// Builder for ProverConfig
#[derive(Debug, Default)]
pub struct ProverConfigBuilder {
    num_threads: Option<usize>,
    tower_level: Option<u8>,
    security_bits: Option<u32>,
}

impl ProverConfigBuilder {
    /// Set the number of threads
    pub fn num_threads(mut self, threads: usize) -> Self {
        self.num_threads = Some(threads);
        self
    }

    /// Set the tower level
    pub fn tower_level(mut self, level: u8) -> Self {
        self.tower_level = Some(level);
        self
    }

    /// Set the security bits
    pub fn security_bits(mut self, bits: u32) -> Self {
        self.security_bits = Some(bits);
        self
    }

    /// Build the ProverConfig
    pub fn build(self) -> ProverConfig {
        let mut config = ProverConfig::default();
        
        if let Some(threads) = self.num_threads {
            config.num_threads = threads;
        }
        
        if let Some(level) = self.tower_level {
            // Clamp to valid range [0, 7]
            config.tower_level = level.min(7);
        }
        
        if let Some(bits) = self.security_bits {
            // Round up to next power of 2, minimum 64
            config.security_bits = if bits <= 64 {
                64
            } else if bits <= 128 {
                128
            } else if bits <= 256 {
                256
            } else {
                512
            };
        }
        
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProverConfig::default();
        assert_eq!(config.num_threads(), 0); // 0 means auto-detect
        assert_eq!(config.tower_level(), 7);
        assert_eq!(config.security_bits(), 128);
    }

    #[test]
    fn test_config_builder() {
        let config = ProverConfig::builder()
            .num_threads(4)
            .tower_level(6)
            .security_bits(256)
            .build();
        
        assert_eq!(config.num_threads(), 4);
        assert_eq!(config.tower_level(), 6);
        assert_eq!(config.security_bits(), 256);
    }

    #[test]
    fn test_config_validation() {
        // Tower level must be between 0 and 7
        let config = ProverConfig::builder()
            .tower_level(8)
            .build();
        assert_eq!(config.tower_level(), 7); // Should clamp to max

        // Security bits should be power of 2 and at least 64
        let config = ProverConfig::builder()
            .security_bits(100)
            .build();
        assert_eq!(config.security_bits(), 128); // Should round up to next power of 2
    }
}