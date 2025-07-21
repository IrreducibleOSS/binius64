use std::time::Instant;

use crate::compiler::circuit::Circuit;

pub fn print_stat(circuit: &Circuit) {
	let cs = circuit.constraint_system();

	println!("Number of gates: {}", circuit.n_gates());
	println!("Number of AND constraints: {}", cs.n_and_constraints());
	println!("Number of MUL constraints: {}", cs.n_mul_constraints());
	println!("Length of value vec: {}", cs.value_vec_len());
	println!("  Constants: {}", cs.constants.len());
	println!("  Inout: {}", cs.n_inout);
	println!("  Witness: {}", cs.n_witness);

	let mut w = circuit.new_witness_filler();
	w.ignore_assertions = true;

	// Now measure the witness filling performance.
	let start = Instant::now();
	let _ = circuit.populate_wire_witness(&mut w);

	let elapsed = start.elapsed();
	println!("fill_witness took {} microseconds", elapsed.as_micros());
}
