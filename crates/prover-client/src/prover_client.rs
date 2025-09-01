use binius_core::constraint_system::{ConstraintSystem, Proof, ValuesData};
use binius_utils::serialization::{DeserializeBytes, SerializeBytes};

use crate::error::{ProverError, Result};
use crate::ffi::prove_serialized;

/// Main interface to the Binius prover using serialization
/// 
/// This provides a clean API that internally handles all serialization/deserialization
/// when communicating with the closed-source prover.
pub struct ProverClient {
    log_inv_rate: u32,
}

impl Default for ProverClient {
    fn default() -> Self {
        Self::new(1) // Default log_inv_rate = 1
    }
}

impl ProverClient {
    /// Create a new prover with the specified log inverse rate
    pub fn new(log_inv_rate: u32) -> Self {
        Self { log_inv_rate }
    }
    
    /// Create a prover with default settings
    pub fn with_defaults() -> Self {
        Self::new(1) // Default log_inv_rate = 1
    }
    
    /// Generate a proof for the given constraint system and witness data
    /// 
    /// # Arguments
    /// * `constraint_system` - The constraint system defining the computation
    /// * `public_witness` - Public input/output values
    /// * `private_witness` - Private witness values
    /// 
    /// # Returns
    /// A deserialized proof that can be verified
    pub fn prove(
        &self,
        constraint_system: &ConstraintSystem,
        public_witness: &ValuesData,
        private_witness: &ValuesData,
    ) -> Result<Proof<'_>> {
        // Serialize constraint system
        let mut cs_bytes = Vec::new();
        constraint_system
            .serialize(&mut cs_bytes)
            .map_err(ProverError::from)?;
        
        // Serialize public witness
        let mut pub_witness_bytes = Vec::new();
        public_witness
            .serialize(&mut pub_witness_bytes)
            .map_err(ProverError::from)?;
        
        // Serialize private witness
        let mut priv_witness_bytes = Vec::new();
        private_witness
            .serialize(&mut priv_witness_bytes)
            .map_err(ProverError::from)?;
        
        // Use the serialized version
        self.prove_serialized(&cs_bytes, &pub_witness_bytes, &priv_witness_bytes)
    }
    
    /// Generate a proof from already-serialized data
    /// 
    /// This is more efficient when you already have serialized bytes,
    /// avoiding unnecessary serialization.
    /// 
    /// # Returns
    /// A deserialized Proof object
    pub fn prove_serialized(
        &self,
        cs_bytes: &[u8],
        pub_witness_bytes: &[u8],
        priv_witness_bytes: &[u8],
    ) -> Result<Proof<'_>> {
        let proof_bytes = prove_serialized(
            cs_bytes,
            pub_witness_bytes,
            priv_witness_bytes,
            self.log_inv_rate,
        )?;
        
        // Deserialize the proof
        Proof::deserialize(&mut proof_bytes.as_slice())
            .map_err(ProverError::from)
    }
    
    /// Generate proof bytes from already-serialized data
    /// 
    /// This is the most efficient option when you want to save the proof
    /// directly without deserializing it first.
    /// 
    /// # Returns
    /// Raw serialized proof bytes
    pub fn prove_serialized_raw(
        &self,
        cs_bytes: &[u8],
        pub_witness_bytes: &[u8],
        priv_witness_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        prove_serialized(cs_bytes, pub_witness_bytes, priv_witness_bytes, self.log_inv_rate)
    }
    
    /// Get the log inverse rate setting
    pub fn log_inv_rate(&self) -> u32 {
        self.log_inv_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prover_client_creation() {
        let client = ProverClient::new(2);
        assert_eq!(client.log_inv_rate(), 2);
        
        let default_client = ProverClient::default();
        assert_eq!(default_client.log_inv_rate(), 1);
    }
    
    // Integration tests that require the FFI library are in tests/integration_test.rs
}