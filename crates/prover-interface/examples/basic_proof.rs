//! Basic example of using the Binius prover interface

use binius_prover_interface::{Prover, ProverConfig, Witness};

fn main() -> binius_prover_interface::Result<()> {
    println!("Binius Prover Interface - Basic Example\n");
    
    // Example 1: Using default configuration
    println!("1. Creating prover with default configuration...");
    let prover = Prover::default()?;
    println!("   Tower level: {}", prover.config().tower_level());
    println!("   Security bits: {}", prover.config().security_bits());
    println!("   Threads: {} (0 = auto-detect)\n", prover.config().num_threads());
    
    // Example 2: Creating a witness
    println!("2. Creating witness from binary values...");
    let witness = Witness::new(vec![1, 0, 1, 1, 0, 1, 0, 1]);
    println!("   Witness length: {} values", witness.len());
    println!("   Witness values: {:?}\n", witness.values());
    
    // Example 3: Generating a proof
    println!("3. Generating proof...");
    let proof = prover.prove(&witness)?;
    println!("   Proof generated successfully!");
    println!("   Proof size: {} bytes\n", proof.len());
    
    // Example 4: Using custom configuration
    println!("4. Creating prover with custom configuration...");
    let custom_config = ProverConfig::builder()
        .num_threads(4)
        .tower_level(6)
        .security_bits(256)
        .build();
    
    let custom_prover = Prover::new(custom_config)?;
    println!("   Custom tower level: {}", custom_prover.config().tower_level());
    println!("   Custom security bits: {}", custom_prover.config().security_bits());
    println!("   Custom threads: {}\n", custom_prover.config().num_threads());
    
    // Example 5: Creating witness from bytes
    println!("5. Creating witness from byte data...");
    let byte_data = vec![0xFF, 0xAA, 0x55, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let byte_witness = Witness::from_bytes(&byte_data);
    println!("   Created witness from {} bytes", byte_data.len());
    
    let proof2 = custom_prover.prove(&byte_witness)?;
    println!("   Proof generated: {} bytes\n", proof2.len());
    
    // Example 6: Proof serialization
    println!("6. Proof serialization...");
    let proof_bytes = proof.to_bytes();
    println!("   Serialized proof to {} bytes", proof_bytes.len());
    
    let restored_proof = binius_prover_interface::Proof::from_bytes(&proof_bytes);
    println!("   Restored proof from bytes");
    assert_eq!(proof, restored_proof);
    println!("   Verification: Proofs match!\n");
    
    // Example 7: Batch proving
    println!("7. Batch proving example...");
    let witnesses = vec![
        Witness::new(vec![1, 0, 1]),
        Witness::new(vec![0, 1, 0, 1]),
        Witness::new(vec![1, 1, 1, 1, 1]),
    ];
    
    for (i, witness) in witnesses.iter().enumerate() {
        let proof = prover.prove(witness)?;
        println!("   Proof {}: {} bytes (witness size: {})", 
                 i + 1, proof.len(), witness.len());
    }
    
    println!("\nAll examples completed successfully!");
    Ok(())
}

#[test]
fn test_example_runs() {
    main().expect("Example should run without errors");
}