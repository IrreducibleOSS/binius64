use binius_examples::{
	ExampleCircuit,
	circuits::keccak::{Instance, KeccakExample, Params},
	prove_verify, setup,
};
use binius_frontend::compiler::CircuitBuilder;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn bench_keccak_permutations(c: &mut Criterion) {
	let mut group = c.benchmark_group("keccak_permutations");

	// Test different numbers of permutations
	// NOTE: Reduced to just 1 permutation for now as larger counts take too long to setup
	let n_permutations = 1;
	group.throughput(Throughput::Elements(n_permutations as u64));

	let params = Params { n_permutations };
	let instance = Instance {};

	let bench_name = format!("n_permutations_{}", n_permutations);

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = KeccakExample::build(params.clone(), &mut builder).unwrap();
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

	group.finish();
}

criterion_group!(keccak, bench_keccak_permutations);
criterion_main!(keccak);
