use std::env;

use binius_examples::{
	ExampleCircuit,
	circuits::ethsign::{EthSignExample, Instance, Params},
	setup,
};
use binius_frontend::compiler::CircuitBuilder;
use binius_verifier::{
	config::StdChallenger,
	transcript::{ProverTranscript, VerifierTranscript},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_ethsign_signatures(c: &mut Criterion) {
	// Parse parameters from environment variables or use defaults
	let n_signatures = env::var("ETHSIGN_SIGNATURES")
		.ok()
		.and_then(|s| s.parse::<usize>().ok())
		.unwrap_or(1);

	let max_msg_len_bytes = env::var("ETHSIGN_MSG_BYTES")
		.ok()
		.and_then(|s| s.parse::<u16>().ok())
		.unwrap_or(67);

	println!(
		"Running ethsign benchmark with {} signatures and {} max message bytes",
		n_signatures, max_msg_len_bytes
	);

	let params = Params {
		n_signatures,
		max_msg_len_bytes,
	};
	let instance = Instance {};

	// Setup phase - do this once outside the benchmark loop
	let mut builder = CircuitBuilder::new();
	let example = EthSignExample::build(params.clone(), &mut builder).unwrap();
	let circuit = builder.build();
	let cs = circuit.constraint_system().clone();
	let (verifier, prover) = setup(cs, 1).unwrap();

	// Create a witness once for proof size measurement
	let mut filler = circuit.new_witness_filler();
	example
		.populate_witness(instance.clone(), &mut filler)
		.unwrap();
	circuit.populate_wire_witness(&mut filler).unwrap();
	let witness = filler.into_value_vec();

	let bench_name = format!("n_sig_{}_msg_{}", n_signatures, max_msg_len_bytes);

	// Measure witness generation time
	{
		let mut group = c.benchmark_group("ethsign_witness_generation");
		group.throughput(Throughput::Elements(n_signatures as u64));

		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &bench_name, |b, _| {
			b.iter(|| {
				let mut filler = circuit.new_witness_filler();
				example
					.populate_witness(instance.clone(), &mut filler)
					.unwrap();
				circuit.populate_wire_witness(&mut filler).unwrap();
				filler.into_value_vec()
			})
		});

		group.finish();
	}

	// Measure proof generation time
	{
		let mut group = c.benchmark_group("ethsign_proof_generation");
		group.throughput(Throughput::Elements(n_signatures as u64));

		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &bench_name, |b, _| {
			b.iter(|| {
				let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
				prover
					.prove(witness.clone(), &mut prover_transcript)
					.unwrap();
				prover_transcript
			})
		});

		group.finish();
	}

	// Generate a proof for verification benchmarking and size measurement
	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	prover
		.prove(witness.clone(), &mut prover_transcript)
		.unwrap();
	let proof_bytes = prover_transcript.finalize();
	let proof_size = proof_bytes.len();

	// Measure proof verification time
	{
		let mut group = c.benchmark_group("ethsign_proof_verification");
		group.throughput(Throughput::Elements(n_signatures as u64));

		group.bench_with_input(BenchmarkId::from_parameter(&bench_name), &bench_name, |b, _| {
			b.iter(|| {
				let mut verifier_transcript =
					VerifierTranscript::new(StdChallenger::default(), proof_bytes.clone());
				verifier
					.verify(witness.public(), &mut verifier_transcript)
					.unwrap();
				verifier_transcript.finalize().unwrap()
			})
		});

		group.finish();
	}

	// Report proof size
	println!(
		"EthSign proof size for {} signatures, {} max bytes: {} bytes",
		n_signatures, max_msg_len_bytes, proof_size
	);
}

criterion_group!(ethsign, bench_ethsign_signatures);
criterion_main!(ethsign);
