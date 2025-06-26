#![allow(unused)]

use circuit::Wire;
use constraint_system::Witness;
use word::Word;

mod circuit;
mod constraint_system;
mod sha256;
mod word;

/// A test circuit that proves a knowledge of preimage for a given state vector S in
///
///     compress512(preimage) = S
///
/// without revealing the preimage, only S.
fn proof_preimage() {
    // Use the test-vector for SHA256 single block message: "abc".
    let mut preimage: [u8; 64] = [0; 64];
    preimage[0..3].copy_from_slice(b"abc");
    preimage[3] = 0x80;
    preimage[63] = 0x18;

    #[rustfmt::skip]
    let expected_state: [u32; 8] = [
        0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
        0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
    ];

    let mut circuit = circuit::CircuitBuilder::new();
    let mut state = sha256::State::iv(&mut circuit);
    let input: [Wire; 16] = std::array::from_fn(|_| circuit.add_private());
    let output: [Wire; 8] = std::array::from_fn(|_| circuit.add_public());
    let compress = sha256::Compress::new(&mut circuit, state, input);

    let state_out = compress.state_out.0.clone();

    // Mask to only low 32-bit.
    let mask32 = circuit.add_constant(Word::MASK_32);
    for (actual_x, expected_x) in compress.state_out.0.iter().zip(output) {
        circuit.assert_eq(circuit.band(*actual_x, mask32), expected_x);
    }

    let circuit = circuit.build();
    let cs = circuit.constraint_system();
    let mut witness = cs.new_witness();

    compress.populate_m(&mut witness, preimage);
    for (i, output) in output.iter().enumerate() {
        witness.set(
            circuit.witness_index(*output),
            Word(expected_state[i] as u64),
        )
    }

    circuit.fill_witness(&mut witness);
    witness.assert_filled();

    println!("Number of AND constraints: {}", cs.n_and_constraints());
    println!("Number of gates: {}", circuit.n_gates());
}

fn main() {
    // proof_preimage();
    sha256_chain();
}

fn sha256_chain() {
    const N: usize = 1 << 10;
    let mut circuit = circuit::CircuitBuilder::new();

    println!("{N} sha256 compress512 invocations");

    let mut compress_vec = Vec::with_capacity(N);

    // First, declare the initial state.
    let mut state = sha256::State::iv(&mut circuit);
    for i in 0..N {
        // Create a new subcircuit builder. This is not necessary but can improve readability
        // and diagnostics.
        let mut sha256_builder = circuit.subcircuit(format!("sha256[{i}]"));

        // Build a new instance of the sha256 verification subcircuit, passing the inputs `m` to it.
        // For the first compression `m` is public but everything else if private.
        let m: [circuit::Wire; 16] = if i == 0 {
            std::array::from_fn(|_| sha256_builder.add_public())
        } else {
            std::array::from_fn(|_| sha256_builder.add_private())
        };
        let compress = sha256::Compress::new(&mut sha256_builder, state, m);
        state = compress.state_out.clone();

        compress_vec.push(compress);
    }

    let circuit = circuit.build();
    let cs = circuit.constraint_system();
    let mut witness = cs.new_witness();

    for compress in &compress_vec {
        compress.populate_m(&mut witness, [0; 64]);
    }
    circuit.fill_witness(&mut witness);
    witness.assert_filled();

    println!("Number of AND constraints: {}", cs.n_and_constraints());
    println!("Number of gates: {}", circuit.n_gates());
}
