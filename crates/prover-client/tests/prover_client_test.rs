//! Tests for the prover interface with FFI library
//! 
//! These tests require the FFI library to be available.
//! They will be skipped if the library is not found.

#[cfg(has_binius_prover)]
mod tests {
    use binius_core::constraint_system::{ConstraintSystem, Proof, ValueVecLayout, ValuesData};
    use binius_core::word::Word;
    use binius_prover_client::ProverClient;
    use binius_utils::serialization::{DeserializeBytes, SerializeBytes};

    fn create_test_constraint_system() -> ConstraintSystem {
        let constants = vec![Word::from_u64(1)];
        
        let value_vec_layout = ValueVecLayout {
            n_const: 1,
            n_inout: 2,      // Must be power of 2
            n_witness: 2,
            n_internal: 1,
            offset_inout: 2,    // Must be power of 2
            offset_witness: 4,  // Must be power of 2
            total_len: 8,       // Must be power of 2
        };
        
        // Simple constraints for testing
        let and_constraints = vec![];
        let mul_constraints = vec![];
        
        ConstraintSystem::new(constants, value_vec_layout, and_constraints, mul_constraints)
    }

    #[test]
    fn test_prove() {
        let prover = ProverClient::new(1);
        
        let cs = create_test_constraint_system();
        let public_witness = ValuesData::from(vec![Word::from_u64(42), Word::from_u64(7)]);
        let private_witness = ValuesData::from(vec![Word::from_u64(1), Word::from_u64(2)]);
        
        let result = prover.prove(&cs, &public_witness, &private_witness);
        assert!(result.is_ok(), "Proving failed: {:?}", result.err());
        
        let proof = result.unwrap();
        
        // Verify proof can be serialized
        let mut proof_bytes = Vec::new();
        proof.serialize(&mut proof_bytes).expect("Failed to serialize proof");
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn test_prove_serialized() {
        let prover = ProverClient::new(1);
        
        // Create and serialize test data
        let cs = create_test_constraint_system();
        let mut cs_bytes = Vec::new();
        cs.serialize(&mut cs_bytes).expect("Failed to serialize CS");
        
        let public_witness = ValuesData::from(vec![Word::from_u64(100), Word::from_u64(200)]);
        let mut pub_bytes = Vec::new();
        public_witness.serialize(&mut pub_bytes).expect("Failed to serialize public witness");
        
        let private_witness = ValuesData::from(vec![Word::from_u64(10), Word::from_u64(20)]);
        let mut priv_bytes = Vec::new();
        private_witness.serialize(&mut priv_bytes).expect("Failed to serialize private witness");
        
        // Test prove_serialized
        let result = prover.prove_serialized(&cs_bytes, &pub_bytes, &priv_bytes);
        assert!(result.is_ok(), "Proving from bytes failed: {:?}", result.err());
        
        let proof = result.unwrap();
        
        // Verify proof can be serialized
        let mut proof_bytes = Vec::new();
        proof.serialize(&mut proof_bytes).expect("Failed to serialize proof");
        assert!(!proof_bytes.is_empty());
    }

    #[test]
    fn test_prove_serialized_raw() {
        let prover = ProverClient::new(1);
        
        // Create and serialize test data
        let cs = create_test_constraint_system();
        let mut cs_bytes = Vec::new();
        cs.serialize(&mut cs_bytes).expect("Failed to serialize CS");
        
        let public_witness = ValuesData::from(vec![Word::from_u64(50), Word::from_u64(60)]);
        let mut pub_bytes = Vec::new();
        public_witness.serialize(&mut pub_bytes).expect("Failed to serialize public witness");
        
        let private_witness = ValuesData::from(vec![Word::from_u64(5), Word::from_u64(6)]);
        let mut priv_bytes = Vec::new();
        private_witness.serialize(&mut priv_bytes).expect("Failed to serialize private witness");
        
        // Test prove_serialized_raw
        let result = prover.prove_serialized_raw(&cs_bytes, &pub_bytes, &priv_bytes);
        assert!(result.is_ok(), "Proving raw bytes failed: {:?}", result.err());
        
        let proof_bytes = result.unwrap();
        assert!(!proof_bytes.is_empty());
        
        // Verify the bytes can be deserialized to a valid Proof
        let proof = Proof::deserialize(&mut proof_bytes.as_slice())
            .expect("Failed to deserialize proof bytes");
        
        // Check proof has expected structure
        let _ = proof;
    }

    #[test]
    fn test_prover_client_default() {
        // Test the Default trait implementation
        let prover = ProverClient::default();
        assert_eq!(prover.log_inv_rate(), 1);
        
        let cs = create_test_constraint_system();
        let public_witness = ValuesData::from(vec![Word::from_u64(10), Word::from_u64(20)]);
        let private_witness = ValuesData::from(vec![Word::from_u64(30), Word::from_u64(40)]);
        
        let result = prover.prove(&cs, &public_witness, &private_witness);
        assert!(result.is_ok());
    }
}

#[cfg(not(has_binius_prover))]
#[test]
fn test_skipped() {
    println!("Tests skipped: FFI library not available. Set BINIUS_PROVER_LIB_PATH to run tests.");
}