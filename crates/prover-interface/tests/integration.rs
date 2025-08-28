// Integration tests for the prover interface

use binius_prover_interface::{Prover, ProverConfig, ProverError, Witness};

#[test]
fn test_end_to_end_proving() {
    // Create prover with custom config
    let config = ProverConfig::builder()
        .num_threads(2)
        .tower_level(7)
        .security_bits(128)
        .build();
    
    let prover = Prover::new(config).expect("Failed to create prover");
    
    // Create a witness
    let witness = Witness::new(vec![1, 0, 1, 1, 0, 1, 0, 1]);
    
    // Generate proof
    let proof = prover.prove(&witness).expect("Failed to generate proof");
    
    // Verify proof has content
    assert!(proof.len() > 0);
    assert!(!proof.is_empty());
    
    // Proof should be reproducible
    let proof2 = prover.prove(&witness).expect("Failed to generate proof");
    assert_eq!(proof.len(), proof2.len());
}

#[test]
fn test_multiple_proofs() {
    let prover = Prover::default().expect("Failed to create prover");
    
    // Generate multiple proofs with different witnesses
    let witnesses = vec![
        Witness::new(vec![1, 0, 1]),
        Witness::new(vec![0, 1, 0, 1]),
        Witness::new(vec![1, 1, 1, 1, 1]),
    ];
    
    for witness in &witnesses {
        let proof = prover.prove(witness).expect("Failed to generate proof");
        assert!(proof.len() > 0);
    }
}

#[test]
fn test_error_handling() {
    let prover = Prover::default().expect("Failed to create prover");
    
    // Empty witness should fail
    let empty_witness = Witness::new(vec![]);
    let result = prover.prove(&empty_witness);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        ProverError::InvalidWitness(msg) => {
            assert!(msg.contains("empty"));
        }
        _ => panic!("Expected InvalidWitness error"),
    }
}

#[test]
fn test_witness_from_bytes() {
    let prover = Prover::default().expect("Failed to create prover");
    
    // Create witness from bytes
    let bytes = vec![0xFF, 0xAA, 0x55, 0x00];
    let witness = Witness::from_bytes(&bytes);
    
    // Should be able to generate proof
    let proof = prover.prove(&witness).expect("Failed to generate proof");
    assert!(proof.len() > 0);
    
    // Verify witness conversion
    assert_eq!(witness.as_bytes(), bytes);
}

#[test]
fn test_proof_serialization() {
    let prover = Prover::default().expect("Failed to create prover");
    let witness = Witness::new(vec![1, 2, 3, 4]);
    
    let proof = prover.prove(&witness).expect("Failed to generate proof");
    
    // Serialize and deserialize proof
    let proof_bytes = proof.to_bytes();
    let restored_proof = binius_prover_interface::Proof::from_bytes(&proof_bytes);
    
    assert_eq!(proof, restored_proof);
    assert_eq!(proof.to_bytes(), restored_proof.to_bytes());
}

#[test]
fn test_config_validation() {
    // Test tower level clamping
    let config = ProverConfig::builder()
        .tower_level(10) // Should be clamped to 7
        .build();
    
    assert_eq!(config.tower_level(), 7);
    
    let prover = Prover::new(config).expect("Failed to create prover");
    assert_eq!(prover.config().tower_level(), 7);
    
    // Test security bits rounding
    let config = ProverConfig::builder()
        .security_bits(100) // Should round to 128
        .build();
    
    assert_eq!(config.security_bits(), 128);
}

#[test]
fn test_concurrent_proving() {
    use std::sync::Arc;
    use std::thread;
    
    let prover = Arc::new(Prover::default().expect("Failed to create prover"));
    
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let prover = Arc::clone(&prover);
            thread::spawn(move || {
                let witness = Witness::new(vec![i as u64; 10]);
                prover.prove(&witness).expect("Failed to generate proof")
            })
        })
        .collect();
    
    for handle in handles {
        let proof = handle.join().expect("Thread panicked");
        assert!(proof.len() > 0);
    }
}