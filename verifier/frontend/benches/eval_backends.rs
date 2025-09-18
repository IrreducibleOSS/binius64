use binius_core::word::Word;
use binius_frontend::{Circuit, CircuitBuilder, Wire};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn build_chain_circuit() -> (Circuit, Vec<Wire>, Vec<Word>) {
	unsafe {
		std::env::set_var("MONBIJOU_LLVM_EVAL", "1");
	}
	let builder = CircuitBuilder::new();
	let mut inputs = Vec::new();
	for _ in 0..8 {
		inputs.push(builder.add_inout());
	}

	let mut acc = inputs[0];
	for i in 1..400 {
		let next = inputs[i % inputs.len()];
		let mix = builder.bxor(acc, next);
		let rotated = builder.rotr(mix, (i % 31) as u32 + 1);
		let third = inputs[(i * 3) % inputs.len()];
		acc = builder.fax(rotated, next, third);
	}

	let _digest = builder.bxor_multi(&inputs);

	let circuit = builder.build();
	unsafe {
		std::env::remove_var("MONBIJOU_LLVM_EVAL");
	}

	let mut rng = StdRng::seed_from_u64(42);
	let assignments: Vec<Word> = inputs.iter().map(|_| Word(rng.random::<u64>())).collect();

	(circuit, inputs, assignments)
}

fn bench_eval_backends(c: &mut Criterion) {
	let (circuit, inputs, assignments) = build_chain_circuit();

	c.bench_function("eval_form_interpreter", |b| {
		b.iter_batched(
			|| {
				let mut filler = circuit.new_witness_filler();
				for (wire, value) in inputs.iter().zip(assignments.iter()) {
					filler[*wire] = *value;
				}
				filler
			},
			|mut filler| {
				circuit.populate_wire_witness(&mut filler).unwrap();
			},
			BatchSize::SmallInput,
		);
	});

	if circuit.has_llvm_backend() {
		c.bench_function("eval_form_llvm", |b| {
			b.iter_batched(
				|| {
					let mut filler = circuit.new_witness_filler();
					for (wire, value) in inputs.iter().zip(assignments.iter()) {
						filler[*wire] = *value;
					}
					filler
				},
				|mut filler| {
					circuit.populate_wire_witness_llvm(&mut filler).unwrap();
				},
				BatchSize::SmallInput,
			);
		});
	}
}

criterion_group!(benches, bench_eval_backends);
criterion_main!(benches);
