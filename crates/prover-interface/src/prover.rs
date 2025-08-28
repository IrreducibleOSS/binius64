// prover.rs - Main prover interface

use crate::config::ProverConfig;
use crate::error::ProverError;
use crate::ffi::ProverHandle;
use crate::types::{Proof, Witness};

/// Main interface to the Binius prover
pub struct Prover {
    handle: ProverHandle,
    config: ProverConfig,
}

impl Prover {
    /// Create a new prover with the given configuration
    pub fn new(config: ProverConfig) -> Result<Self, ProverError> {
        let handle = ProverHandle::create(&config)?;
        Ok(Self { handle, config })
    }
    
    /// Create a new prover with default configuration
    pub fn default() -> Result<Self, ProverError> {
        Self::new(ProverConfig::default())
    }
    
    /// Generate a proof for the given witness
    pub fn prove(&self, witness: &Witness) -> Result<Proof, ProverError> {
        // Validate witness
        if witness.is_empty() {
            return Err(ProverError::InvalidWitness("Witness cannot be empty".to_string()));
        }
        
        // Generate proof using FFI
        self.handle.prove(witness)
    }
    
    /// Get the current configuration
    pub fn config(&self) -> &ProverConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prover_creation() {
        let config = ProverConfig::default();
        let prover = Prover::new(config);
        assert!(prover.is_ok());
    }
    
    #[test]
    fn test_prover_default() {
        let prover = Prover::default();
        assert!(prover.is_ok());
        assert_eq!(prover.unwrap().config().tower_level(), 7);
    }
    
    #[test]
    fn test_proof_generation() {
        let prover = Prover::default().unwrap();
        let witness = Witness::new(vec![1, 0, 1, 1]);
        let proof = prover.prove(&witness);
        assert!(proof.is_ok());
        assert!(proof.unwrap().len() > 0);
    }
    
    #[test]
    fn test_empty_witness_rejected() {
        let prover = Prover::default().unwrap();
        let witness = Witness::new(vec![]);
        let proof = prover.prove(&witness);
        assert!(proof.is_err());
        assert!(matches!(proof.unwrap_err(), ProverError::InvalidWitness(_)));
    }
    
    #[test]
    fn test_prover_with_custom_config() {
        let config = ProverConfig::builder()
            .num_threads(4)
            .tower_level(6)
            .security_bits(256)
            .build();
        
        let prover = Prover::new(config).unwrap();
        assert_eq!(prover.config().num_threads(), 4);
        assert_eq!(prover.config().tower_level(), 6);
        assert_eq!(prover.config().security_bits(), 256);
    }
}