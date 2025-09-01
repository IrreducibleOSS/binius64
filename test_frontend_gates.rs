use binius_frontend::compiler::CircuitBuilder;
use binius_frontend::circuits::sha256::Sha256;

fn main() {
    let mut builder = CircuitBuilder::new();
    
    // Create SHA256 circuit for max 256 bytes
    let len_wire = builder.add_witness();
    let digest_wires = std::array::from_fn(|_| builder.add_witness());
    let mut message_wires = Vec::new();
    for _ in 0..32 {  // 256 bytes / 8 bytes per wire = 32 wires
        message_wires.push(builder.add_witness());
    }
    
    let _sha256 = Sha256::new(&mut builder, len_wire, digest_wires, message_wires);
    
    let circuit = builder.build();
    println!("Frontend SHA256 circuit: {} gates", circuit.n_gates());
}