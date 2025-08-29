use binius_examples::{
	ExampleCircuit,
	circuits::ethsign::{EthSignExample, Instance, Params},
	prove_verify, setup,
};
use binius_frontend::compiler::CircuitBuilder;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn bench_ethsign_signatures(c: &mut Criterion) {
	let mut group = c.benchmark_group("ethsign_signatures");

	// Test different combinations of signatures and message sizes
	// NOTE: Reduced test cases as larger counts take too long to setup
	let test_cases = [(1, 64), (1, 67)];

	for (n_signatures, max_msg_len_bytes) in test_cases {
		group.throughput(Throughput::Elements(n_signatures as u64));

		let params = Params {
			n_signatures,
			max_msg_len_bytes,
		};
		let instance = Instance {};

		let bench_name = format!("n_sig_{}_msg_{}", n_signatures, max_msg_len_bytes);

		// Setup phase - do this once outside the benchmark loop
		let mut builder = CircuitBuilder::new();
		let example = EthSignExample::build(params.clone(), &mut builder).unwrap();
		let circuit = builder.build();
		let cs = circuit.constraint_system().clone();
		let (verifier, prover) = setup(cs, 1).unwrap();

		group.bench_function(bench_name, |b| {
			b.iter(|| {
				// Only benchmark witness generation and prove/verify
				let mut filler = circuit.new_witness_filler();
				example
					.populate_witness(instance.clone(), &mut filler)
					.unwrap();
				circuit.populate_wire_witness(&mut filler).unwrap();
				let witness = filler.into_value_vec();
				prove_verify(&verifier, &prover, witness).unwrap()
			})
		});
	}

	group.finish();
}

criterion_group!(ethsign, bench_ethsign_signatures);
criterion_main!(ethsign);
