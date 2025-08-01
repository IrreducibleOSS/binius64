// Copyright 2025 Irreducible Inc.

use std::{cell::RefCell, sync::Once};

use binius_field::Field;
use binius_frontend::{
	compiler::CircuitBuilder,
	constraint_system::{AndConstraint, ConstraintSystem, MulConstraint, ValueVec},
	constraint_verifier::{eval_operand, verify_constraints},
	word::Word,
};
use binius_math::univariate::lagrange_evals;
use binius_prover::protocols::shift::{OperatorData, build_prover_constraint_system, prove};
use binius_transcript::ProverTranscript;
use binius_utils::checked_arithmetics::strict_log_2;
use binius_verifier::{
	config::{StdChallenger, WORD_SIZE_BITS},
	protocols::shift::{
		OperatorData as VerifierOperatorData, inner_product as inner_product_scalar,
		tensor_expand as tensor_expand_scalar, verify,
	},
};
use criterion::{Criterion, criterion_group, criterion_main};
use itertools::Itertools;
use rand::{SeedableRng, rngs::StdRng};

// Tracing setup for benchmarks (similar to tests)
static INIT_BENCH_TRACING: Once = Once::new();

thread_local! {
	static BENCH_CHROME_GUARD: RefCell<Option<tracing_chrome::FlushGuard>> = RefCell::new(None);
}

fn init_bench_tracing(bench_name: &str) {
	INIT_BENCH_TRACING.call_once(|| {
		// Create chrome trace layer for trace file generation
		let trace_file = format!("bench_trace_{}.json", bench_name.replace(' ', "_"));
		let (chrome_layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
			.file(&trace_file)
			.include_args(true)
			.build();

		// Store guard in thread-local storage
		BENCH_CHROME_GUARD.with(|g| {
			*g.borrow_mut() = Some(guard);
		});

		use tracing_subscriber::prelude::*;
		tracing_subscriber::registry().with(chrome_layer).init();
		println!(
			"Tracing initialized for benchmark '{}', trace will be saved to {}",
			bench_name, trace_file
		);
	});
}

// // Function to manually flush trace at end of benchmark
// fn flush_bench_trace() {
// 	BENCH_CHROME_GUARD.with(|g| {
// 		if let Some(guard) = g.borrow_mut().take() {
// 			drop(guard); // This should flush the trace
// 			println!("Trace flushed successfully");
// 		}
// 	});
// }

pub fn create_rs256_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::{fixed_byte_vec::FixedByteVec, rs256::Rs256Verify};
	use rand::{SeedableRng, rngs::StdRng};
	use rsa::{
		RsaPrivateKey, RsaPublicKey,
		pkcs1v15::SigningKey,
		sha2::{Digest, Sha256},
		signature::{SignatureEncoding, Signer},
		traits::PublicKeyParts,
	};

	let mut builder = CircuitBuilder::new();
	let max_message_len: usize = 256; // Maximum message length

	// Setup circuit using the new Rs256Verify API
	let signature_bytes = FixedByteVec::new_inout(&mut builder, 256);
	let modulus_bytes = FixedByteVec::new_inout(&mut builder, 256);
	let message = FixedByteVec::new_witness(&mut builder, max_message_len);

	// Create the RS256 circuit with new API (only 4 arguments)
	let rs256 = Rs256Verify::new(&mut builder, message, signature_bytes, modulus_bytes);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Generate real RSA signature and witness data (following the working test pattern)
	let mut rng = StdRng::seed_from_u64(42);
	let bits = 2048;
	let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
	let public_key = RsaPublicKey::from(&private_key);

	let message_bytes = b"Test message for RS256 verification";
	let signing_key = SigningKey::<Sha256>::new(private_key);
	let signature_obj = signing_key.sign(message_bytes);

	// Get signature and modulus as byte arrays
	let signature_bytes = signature_obj.to_bytes();
	let modulus_bytes = public_key.n().to_be_bytes();

	// Populate using the exact same pattern as the working test
	let hash = Sha256::digest(message_bytes);
	rs256.populate_rsa(&mut witness_filler, &signature_bytes, &modulus_bytes);
	rs256.populate_message_len(&mut witness_filler, message_bytes.len());
	rs256.populate_message(&mut witness_filler, message_bytes);
	rs256
		.sha256
		.populate_digest(&mut witness_filler, hash.into());

	// Populate wire witness using built circuit
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

pub fn create_base64_cs_with_witness() -> (ConstraintSystem, ValueVec) {
	use binius_frontend::circuits::base64::Base64UrlSafe;

	let builder = CircuitBuilder::new();
	let max_len_decoded: usize = 1368 * 10; // Must be multiple of 24

	// Create wires for Base64 circuit
	let decoded: Vec<binius_frontend::compiler::Wire> = (0..max_len_decoded / 8)
		.map(|_| builder.add_inout())
		.collect();
	let encoded: Vec<binius_frontend::compiler::Wire> = (0..max_len_decoded / 6)
		.map(|_| builder.add_inout())
		.collect();
	let len_decoded = builder.add_inout();

	// Create the Base64 circuit
	let base64 = Base64UrlSafe::new(&builder, max_len_decoded, decoded, encoded, len_decoded);

	let circuit = builder.build();
	let mut witness_filler = circuit.new_witness_filler();

	// Test with large text for scaling up the constraint system
	let decoded_data = br#"Lorem ipsum dolor sit amet consectetur adipiscing elit quisque faucibus ex sapien vitae pellentesque sem placerat in id cursus mi pretium tellus duis convallis tempus leo eu aenean sed diam urna tempor pulvinar vivamus fringilla lacus nec metus bibendum egestas iaculis massa nisl malesuada lacinia integer nunc posuere ut hendrerit semper vel class aptent taciti sociosqu ad litora torquent per conubia nostra inceptos himenaeos orci varius natoque penatibus et magnis dis parturient montes nascetur ridiculus mus donec rhoncus eros lobortis nulla molestie mattis scelerisque maximus eget fermentum odio phasellus non purus est efficitur laoreet mauris pharetra vestibulum fusce dictum risus blandit quis suspendisse aliquet nisi sodales consequat magna ante condimentum neque at luctus nibh finibus facilisis dapibus etiam interdum tortor ligula congue sollicitudin erat viverra ac tincidunt nam porta elementum a enim euismod quam justo lectus commodo augue arcu dignissim velit aliquam imperdiet mollis nullam volutpat porttitor ullamcorper rutrum gravida cras eleifend turpis fames primis vulputate ornare sagittis vehicula praesent dui felis venenatis ultrices proin libero feugiat tristique accumsan maecenas potenti ultricies habitant morbi senectus netus suscipit auctor curabitur facilisi cubilia curae hac habitasse platea dictumst lorem ipsum dolor sit amet consectetur adipiscing elit quisque faucibus ex sapien vitae pellentesque sem placerat in id cursus mi pretium tellus duis convallis tempus leo eu aenean sed diam urna tempor pulvinar vivamus fringilla lacus nec metus bibendum egestas iaculis massa nisl malesuada lacinia integer nunc posuere ut hendrerit semper vel class aptent taciti sociosqu ad litora torquent per conubia nostra inceptos himenaeos orci varius natoque penatibus et magnis dis parturient montes nascetur ridiculus mus donec rhoncus eros lobortis nulla molestie mattis scelerisque maximus eget fermentum odio phasellus non purus est efficitur laoreet mauris pharetra vestibulum fusce dictum risus blandit quis suspendisse aliquet nisi sodales consequat magna ante condimentum neque at luctus nibh finibus facilisis dapibus etiam interdum tortor ligula congue sollicitudin erat viverra ac tincidunt nam porta elementum a enim euismod quam justo lectus commodo augue arcu dignissim velit aliquam imperdiet mollis nullam volutpat porttitor ullamcorper rutrum gravida cras eleifend turpis fames primis vulputate ornare sagittis vehicula praesent dui felis venenatis ultrices proin libero feugiat tristique accumsan maecenas potenti ultricies habitant morbi senectus netus suscipit auctor curabitur facilisi cubilia curae hac habitasse platea dictumst lorem ipsum dolor sit amet consectetur adipiscing elit quisque faucibus ex sapien vitae pellentesque sem placerat in id cursus mi pretium tellus duis convallis tempus leo eu aenean sed diam urna tempor pulvinar vivamus fringilla lacus nec metus bibendum egestas iaculis massa nisl malesuada lacinia integer nunc posuere ut hendrerit semper vel class aptent taciti sociosqu ad litora torquent per conubia nostra inceptos himenaeos orci varius natoque penatibus et magnis dis parturient montes nascetur ridiculus mus donec rhoncus eros lobortis nulla molestie mattis scelerisque maximus eget fermentum odio phasellus non purus est efficitur laoreet mauris pharetra vestibulum fusce dictum risus blandit quis suspendisse aliquet nisi sodales consequat magna ante condimentum neque at luctus nibh finibus facilisis dapibus etiam interdum tortor ligula congue sollicitudin erat viverra ac tincidunt nam porta elementum a enim euismod quam justo lectus commodo augue arcu dignissim velit aliquam imperdiet mollis nullam volutpat porttitor ullamcorper rutrum gravida cras eleifend turpis fames primis vulputate ornare sagittis vehicula praesent dui felis venenatis ultrices proin libero feugiat tristique accumsan maecenas potenti ultricies habitant morbi senectus netus suscipit auctor curabitur facilisi cubilia curae hac habitasse platea dictumst lorem ipsum dolor sit amet consectetur adipiscing elit quisque faucibus ex sapien vitae pellentesque sem placerat in id cursus mi pretium tellus duis convallis tempus leo eu aenean sed diam urna tempor pulvinar vivamus fringilla lacus nec metus bibendum egestas iaculis massa nisl malesuada lacinia integer nunc posuere ut hendrerit semper vel class aptent taciti sociosqu ad litora torquent per conubia nostra inceptos himenaeos orci varius natoque penatibus et magnis dis parturient montes nascetur ridiculus mus donec rhoncus eros lobortis nulla molestie mattis scelerisque maximus eget fermentum odio phasellus non purus est efficitur laoreet mauris pharetra vestibulum fusce dictum risus blandit quis suspendisse aliquet nisi sodales consequat magna ante condimentum neque at luctus nibh finibus facilisis dapibus etiam interdum tortor ligula congue sollicitudin erat viverra ac tincidunt nam porta elementum a enim euismod quam justo lectus commodo augue arcu dignissim velit aliquam imperdiet mollis nullam volutpat porttitor ullamcorper rutrum gravida cras eleifend turpis fames primis vulputate ornare sagittis vehicula praesent dui felis venenatis ultrices proin libero feugiat tristique accumsan maecenas potenti ultricies habitant morbi senectus netus suscipit auctor curabitur facilisi cubilia curae hac habitasse platea dictumst lorem ipsum dolor sit amet consectetur adipiscing elit quisque faucibus ex sapien vitae pellentesque sem placerat in id cursus mi pretium tellus duis convallis tempus leo eu aenean sed diam urna tempor pulvinar vivamus fringilla lacus nec metus bibendum egestas iaculis massa nisl malesuada lacinia integer nunc posuere ut hendrerit semper vel class aptent taciti sociosqu ad litora torquent per conubia nostra inceptos himenaeos orci varius natoque penatibus et magnis dis parturient montes nascetur ridiculus mus donec rhoncus eros lobortis nulla molestie mattis scelerisque maximus eget fermentum odio phasellus non purus est efficitur laoreet mauris pharetra vestibulum fusce dictum risus blandit quis suspendisse aliquet nisi sodales consequat magna ante condimentum neque at luctus nibh finibus facilisis dapibus etiam interdum tortor ligula congue sollicitudin erat viverra ac tincidunt nam porta elementum a enim euismod quam justo lectus commodo augue arcu dignissim velit aliquam imperdiet mollis nullam volutpat porttitor ullamcorper rutrum gravida cras eleifend turpis fames primis vulputate ornare sagittis vehicula praesent dui felis venenatis ultrices proin libero feugiat tristique accumsan maecenas potenti ultricies habitant morbi senectus netus suscipit auctor curabitur facilisi cubilia curae hac habitasse platea dictumst lorem ipsum dolor sit amet consectetur adipiscing elit quisque faucibus ex sapien vitae pellentesque sem placerat in id cursus mi pretium tellus duis convallis tempus leo eu aenean sed diam urna tempor pulvinar vivamus fringilla lacus nec metus bibendum egestas iaculis massa nisl malesuada lacinia integer nunc posuere ut hendrerit semper vel class aptent taciti sociosqu ad litora torquent per conubia nostra inceptos himenaeos orci varius natoque penatibus et."#;
	let encoded_data = b"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQgY29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0IHF1aXNxdWUgZmF1Y2lidXMgZXggc2FwaWVuIHZpdGFlIHBlbGxlbnRlc3F1ZSBzZW0gcGxhY2VyYXQgaW4gaWQgY3Vyc3VzIG1pIHByZXRpdW0gdGVsbHVzIGR1aXMgY29udmFsbGlzIHRlbXB1cyBsZW8gZXUgYWVuZWFuIHNlZCBkaWFtIHVybmEgdGVtcG9yIHB1bHZpbmFyIHZpdmFtdXMgZnJpbmdpbGxhIGxhY3VzIG5lYyBtZXR1cyBiaWJlbmR1bSBlZ2VzdGFzIGlhY3VsaXMgbWFzc2EgbmlzbCBtYWxlc3VhZGEgbGFjaW5pYSBpbnRlZ2VyIG51bmMgcG9zdWVyZSB1dCBoZW5kcmVyaXQgc2VtcGVyIHZlbCBjbGFzcyBhcHRlbnQgdGFjaXRpIHNvY2lvc3F1IGFkIGxpdG9yYSB0b3JxdWVudCBwZXIgY29udWJpYSBub3N0cmEgaW5jZXB0b3MgaGltZW5hZW9zIG9yY2kgdmFyaXVzIG5hdG9xdWUgcGVuYXRpYnVzIGV0IG1hZ25pcyBkaXMgcGFydHVyaWVudCBtb250ZXMgbmFzY2V0dXIgcmlkaWN1bHVzIG11cyBkb25lYyByaG9uY3VzIGVyb3MgbG9ib3J0aXMgbnVsbGEgbW9sZXN0aWUgbWF0dGlzIHNjZWxlcmlzcXVlIG1heGltdXMgZWdldCBmZXJtZW50dW0gb2RpbyBwaGFzZWxsdXMgbm9uIHB1cnVzIGVzdCBlZmZpY2l0dXIgbGFvcmVldCBtYXVyaXMgcGhhcmV0cmEgdmVzdGlidWx1bSBmdXNjZSBkaWN0dW0gcmlzdXMgYmxhbmRpdCBxdWlzIHN1c3BlbmRpc3NlIGFsaXF1ZXQgbmlzaSBzb2RhbGVzIGNvbnNlcXVhdCBtYWduYSBhbnRlIGNvbmRpbWVudHVtIG5lcXVlIGF0IGx1Y3R1cyBuaWJoIGZpbmlidXMgZmFjaWxpc2lzIGRhcGlidXMgZXRpYW0gaW50ZXJkdW0gdG9ydG9yIGxpZ3VsYSBjb25ndWUgc29sbGljaXR1ZGluIGVyYXQgdml2ZXJyYSBhYyB0aW5jaWR1bnQgbmFtIHBvcnRhIGVsZW1lbnR1bSBhIGVuaW0gZXVpc21vZCBxdWFtIGp1c3RvIGxlY3R1cyBjb21tb2RvIGF1Z3VlIGFyY3UgZGlnbmlzc2ltIHZlbGl0IGFsaXF1YW0gaW1wZXJkaWV0IG1vbGxpcyBudWxsYW0gdm9sdXRwYXQgcG9ydHRpdG9yIHVsbGFtY29ycGVyIHJ1dHJ1bSBncmF2aWRhIGNyYXMgZWxlaWZlbmQgdHVycGlzIGZhbWVzIHByaW1pcyB2dWxwdXRhdGUgb3JuYXJlIHNhZ2l0dGlzIHZlaGljdWxhIHByYWVzZW50IGR1aSBmZWxpcyB2ZW5lbmF0aXMgdWx0cmljZXMgcHJvaW4gbGliZXJvIGZldWdpYXQgdHJpc3RpcXVlIGFjY3Vtc2FuIG1hZWNlbmFzIHBvdGVudGkgdWx0cmljaWVzIGhhYml0YW50IG1vcmJpIHNlbmVjdHVzIG5ldHVzIHN1c2NpcGl0IGF1Y3RvciBjdXJhYml0dXIgZmFjaWxpc2kgY3ViaWxpYSBjdXJhZSBoYWMgaGFiaXRhc3NlIHBsYXRlYSBkaWN0dW1zdCBsb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQgcXVpc3F1ZSBmYXVjaWJ1cyBleCBzYXBpZW4gdml0YWUgcGVsbGVudGVzcXVlIHNlbSBwbGFjZXJhdCBpbiBpZCBjdXJzdXMgbWkgcHJldGl1bSB0ZWxsdXMgZHVpcyBjb252YWxsaXMgdGVtcHVzIGxlbyBldSBhZW5lYW4gc2VkIGRpYW0gdXJuYSB0ZW1wb3IgcHVsdmluYXIgdml2YW11cyBmcmluZ2lsbGEgbGFjdXMgbmVjIG1ldHVzIGJpYmVuZHVtIGVnZXN0YXMgaWFjdWxpcyBtYXNzYSBuaXNsIG1hbGVzdWFkYSBsYWNpbmlhIGludGVnZXIgbnVuYyBwb3N1ZXJlIHV0IGhlbmRyZXJpdCBzZW1wZXIgdmVsIGNsYXNzIGFwdGVudCB0YWNpdGkgc29jaW9zcXUgYWQgbGl0b3JhIHRvcnF1ZW50IHBlciBjb251YmlhIG5vc3RyYSBpbmNlcHRvcyBoaW1lbmFlb3Mgb3JjaSB2YXJpdXMgbmF0b3F1ZSBwZW5hdGlidXMgZXQgbWFnbmlzIGRpcyBwYXJ0dXJpZW50IG1vbnRlcyBuYXNjZXR1ciByaWRpY3VsdXMgbXVzIGRvbmVjIHJob25jdXMgZXJvcyBsb2JvcnRpcyBudWxsYSBtb2xlc3RpZSBtYXR0aXMgc2NlbGVyaXNxdWUgbWF4aW11cyBlZ2V0IGZlcm1lbnR1bSBvZGlvIHBoYXNlbGx1cyBub24gcHVydXMgZXN0IGVmZmljaXR1ciBsYW9yZWV0IG1hdXJpcyBwaGFyZXRyYSB2ZXN0aWJ1bHVtIGZ1c2NlIGRpY3R1bSByaXN1cyBibGFuZGl0IHF1aXMgc3VzcGVuZGlzc2UgYWxpcXVldCBuaXNpIHNvZGFsZXMgY29uc2VxdWF0IG1hZ25hIGFudGUgY29uZGltZW50dW0gbmVxdWUgYXQgbHVjdHVzIG5pYmggZmluaWJ1cyBmYWNpbGlzaXMgZGFwaWJ1cyBldGlhbSBpbnRlcmR1bSB0b3J0b3IgbGlndWxhIGNvbmd1ZSBzb2xsaWNpdHVkaW4gZXJhdCB2aXZlcnJhIGFjIHRpbmNpZHVudCBuYW0gcG9ydGEgZWxlbWVudHVtIGEgZW5pbSBldWlzbW9kIHF1YW0ganVzdG8gbGVjdHVzIGNvbW1vZG8gYXVndWUgYXJjdSBkaWduaXNzaW0gdmVsaXQgYWxpcXVhbSBpbXBlcmRpZXQgbW9sbGlzIG51bGxhbSB2b2x1dHBhdCBwb3J0dGl0b3IgdWxsYW1jb3JwZXIgcnV0cnVtIGdyYXZpZGEgY3JhcyBlbGVpZmVuZCB0dXJwaXMgZmFtZXMgcHJpbWlzIHZ1bHB1dGF0ZSBvcm5hcmUgc2FnaXR0aXMgdmVoaWN1bGEgcHJhZXNlbnQgZHVpIGZlbGlzIHZlbmVuYXRpcyB1bHRyaWNlcyBwcm9pbiBsaWJlcm8gZmV1Z2lhdCB0cmlzdGlxdWUgYWNjdW1zYW4gbWFlY2VuYXMgcG90ZW50aSB1bHRyaWNpZXMgaGFiaXRhbnQgbW9yYmkgc2VuZWN0dXMgbmV0dXMgc3VzY2lwaXQgYXVjdG9yIGN1cmFiaXR1ciBmYWNpbGlzaSBjdWJpbGlhIGN1cmFlIGhhYyBoYWJpdGFzc2UgcGxhdGVhIGRpY3R1bXN0IGxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0IGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCBxdWlzcXVlIGZhdWNpYnVzIGV4IHNhcGllbiB2aXRhZSBwZWxsZW50ZXNxdWUgc2VtIHBsYWNlcmF0IGluIGlkIGN1cnN1cyBtaSBwcmV0aXVtIHRlbGx1cyBkdWlzIGNvbnZhbGxpcyB0ZW1wdXMgbGVvIGV1IGFlbmVhbiBzZWQgZGlhbSB1cm5hIHRlbXBvciBwdWx2aW5hciB2aXZhbXVzIGZyaW5naWxsYSBsYWN1cyBuZWMgbWV0dXMgYmliZW5kdW0gZWdlc3RhcyBpYWN1bGlzIG1hc3NhIG5pc2wgbWFsZXN1YWRhIGxhY2luaWEgaW50ZWdlciBudW5jIHBvc3VlcmUgdXQgaGVuZHJlcml0IHNlbXBlciB2ZWwgY2xhc3MgYXB0ZW50IHRhY2l0aSBzb2Npb3NxdSBhZCBsaXRvcmEgdG9ycXVlbnQgcGVyIGNvbnViaWEgbm9zdHJhIGluY2VwdG9zIGhpbWVuYWVvcyBvcmNpIHZhcml1cyBuYXRvcXVlIHBlbmF0aWJ1cyBldCBtYWduaXMgZGlzIHBhcnR1cmllbnQgbW9udGVzIG5hc2NldHVyIHJpZGljdWx1cyBtdXMgZG9uZWMgcmhvbmN1cyBlcm9zIGxvYm9ydGlzIG51bGxhIG1vbGVzdGllIG1hdHRpcyBzY2VsZXJpc3F1ZSBtYXhpbXVzIGVnZXQgZmVybWVudHVtIG9kaW8gcGhhc2VsbHVzIG5vbiBwdXJ1cyBlc3QgZWZmaWNpdHVyIGxhb3JlZXQgbWF1cmlzIHBoYXJldHJhIHZlc3RpYnVsdW0gZnVzY2UgZGljdHVtIHJpc3VzIGJsYW5kaXQgcXVpcyBzdXNwZW5kaXNzZSBhbGlxdWV0IG5pc2kgc29kYWxlcyBjb25zZXF1YXQgbWFnbmEgYW50ZSBjb25kaW1lbnR1bSBuZXF1ZSBhdCBsdWN0dXMgbmliaCBmaW5pYnVzIGZhY2lsaXNpcyBkYXBpYnVzIGV0aWFtIGludGVyZHVtIHRvcnRvciBsaWd1bGEgY29uZ3VlIHNvbGxpY2l0dWRpbiBlcmF0IHZpdmVycmEgYWMgdGluY2lkdW50IG5hbSBwb3J0YSBlbGVtZW50dW0gYSBlbmltIGV1aXNtb2QgcXVhbSBqdXN0byBsZWN0dXMgY29tbW9kbyBhdWd1ZSBhcmN1IGRpZ25pc3NpbSB2ZWxpdCBhbGlxdWFtIGltcGVyZGlldCBtb2xsaXMgbnVsbGFtIHZvbHV0cGF0IHBvcnR0aXRvciB1bGxhbWNvcnBlciBydXRydW0gZ3JhdmlkYSBjcmFzIGVsZWlmZW5kIHR1cnBpcyBmYW1lcyBwcmltaXMgdnVscHV0YXRlIG9ybmFyZSBzYWdpdHRpcyB2ZWhpY3VsYSBwcmFlc2VudCBkdWkgZmVsaXMgdmVuZW5hdGlzIHVsdHJpY2VzIHByb2luIGxpYmVybyBmZXVnaWF0IHRyaXN0aXF1ZSBhY2N1bXNhbiBtYWVjZW5hcyBwb3RlbnRpIHVsdHJpY2llcyBoYWJpdGFudCBtb3JiaSBzZW5lY3R1cyBuZXR1cyBzdXNjaXBpdCBhdWN0b3IgY3VyYWJpdHVyIGZhY2lsaXNpIGN1YmlsaWEgY3VyYWUgaGFjIGhhYml0YXNzZSBwbGF0ZWEgZGljdHVtc3QgbG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQgY29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0IHF1aXNxdWUgZmF1Y2lidXMgZXggc2FwaWVuIHZpdGFlIHBlbGxlbnRlc3F1ZSBzZW0gcGxhY2VyYXQgaW4gaWQgY3Vyc3VzIG1pIHByZXRpdW0gdGVsbHVzIGR1aXMgY29udmFsbGlzIHRlbXB1cyBsZW8gZXUgYWVuZWFuIHNlZCBkaWFtIHVybmEgdGVtcG9yIHB1bHZpbmFyIHZpdmFtdXMgZnJpbmdpbGxhIGxhY3VzIG5lYyBtZXR1cyBiaWJlbmR1bSBlZ2VzdGFzIGlhY3VsaXMgbWFzc2EgbmlzbCBtYWxlc3VhZGEgbGFjaW5pYSBpbnRlZ2VyIG51bmMgcG9zdWVyZSB1dCBoZW5kcmVyaXQgc2VtcGVyIHZlbCBjbGFzcyBhcHRlbnQgdGFjaXRpIHNvY2lvc3F1IGFkIGxpdG9yYSB0b3JxdWVudCBwZXIgY29udWJpYSBub3N0cmEgaW5jZXB0b3MgaGltZW5hZW9zIG9yY2kgdmFyaXVzIG5hdG9xdWUgcGVuYXRpYnVzIGV0IG1hZ25pcyBkaXMgcGFydHVyaWVudCBtb250ZXMgbmFzY2V0dXIgcmlkaWN1bHVzIG11cyBkb25lYyByaG9uY3VzIGVyb3MgbG9ib3J0aXMgbnVsbGEgbW9sZXN0aWUgbWF0dGlzIHNjZWxlcmlzcXVlIG1heGltdXMgZWdldCBmZXJtZW50dW0gb2RpbyBwaGFzZWxsdXMgbm9uIHB1cnVzIGVzdCBlZmZpY2l0dXIgbGFvcmVldCBtYXVyaXMgcGhhcmV0cmEgdmVzdGlidWx1bSBmdXNjZSBkaWN0dW0gcmlzdXMgYmxhbmRpdCBxdWlzIHN1c3BlbmRpc3NlIGFsaXF1ZXQgbmlzaSBzb2RhbGVzIGNvbnNlcXVhdCBtYWduYSBhbnRlIGNvbmRpbWVudHVtIG5lcXVlIGF0IGx1Y3R1cyBuaWJoIGZpbmlidXMgZmFjaWxpc2lzIGRhcGlidXMgZXRpYW0gaW50ZXJkdW0gdG9ydG9yIGxpZ3VsYSBjb25ndWUgc29sbGljaXR1ZGluIGVyYXQgdml2ZXJyYSBhYyB0aW5jaWR1bnQgbmFtIHBvcnRhIGVsZW1lbnR1bSBhIGVuaW0gZXVpc21vZCBxdWFtIGp1c3RvIGxlY3R1cyBjb21tb2RvIGF1Z3VlIGFyY3UgZGlnbmlzc2ltIHZlbGl0IGFsaXF1YW0gaW1wZXJkaWV0IG1vbGxpcyBudWxsYW0gdm9sdXRwYXQgcG9ydHRpdG9yIHVsbGFtY29ycGVyIHJ1dHJ1bSBncmF2aWRhIGNyYXMgZWxlaWZlbmQgdHVycGlzIGZhbWVzIHByaW1pcyB2dWxwdXRhdGUgb3JuYXJlIHNhZ2l0dGlzIHZlaGljdWxhIHByYWVzZW50IGR1aSBmZWxpcyB2ZW5lbmF0aXMgdWx0cmljZXMgcHJvaW4gbGliZXJvIGZldWdpYXQgdHJpc3RpcXVlIGFjY3Vtc2FuIG1hZWNlbmFzIHBvdGVudGkgdWx0cmljaWVzIGhhYml0YW50IG1vcmJpIHNlbmVjdHVzIG5ldHVzIHN1c2NpcGl0IGF1Y3RvciBjdXJhYml0dXIgZmFjaWxpc2kgY3ViaWxpYSBjdXJhZSBoYWMgaGFiaXRhc3NlIHBsYXRlYSBkaWN0dW1zdCBsb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQgcXVpc3F1ZSBmYXVjaWJ1cyBleCBzYXBpZW4gdml0YWUgcGVsbGVudGVzcXVlIHNlbSBwbGFjZXJhdCBpbiBpZCBjdXJzdXMgbWkgcHJldGl1bSB0ZWxsdXMgZHVpcyBjb252YWxsaXMgdGVtcHVzIGxlbyBldSBhZW5lYW4gc2VkIGRpYW0gdXJuYSB0ZW1wb3IgcHVsdmluYXIgdml2YW11cyBmcmluZ2lsbGEgbGFjdXMgbmVjIG1ldHVzIGJpYmVuZHVtIGVnZXN0YXMgaWFjdWxpcyBtYXNzYSBuaXNsIG1hbGVzdWFkYSBsYWNpbmlhIGludGVnZXIgbnVuYyBwb3N1ZXJlIHV0IGhlbmRyZXJpdCBzZW1wZXIgdmVsIGNsYXNzIGFwdGVudCB0YWNpdGkgc29jaW9zcXUgYWQgbGl0b3JhIHRvcnF1ZW50IHBlciBjb251YmlhIG5vc3RyYSBpbmNlcHRvcyBoaW1lbmFlb3Mgb3JjaSB2YXJpdXMgbmF0b3F1ZSBwZW5hdGlidXMgZXQgbWFnbmlzIGRpcyBwYXJ0dXJpZW50IG1vbnRlcyBuYXNjZXR1ciByaWRpY3VsdXMgbXVzIGRvbmVjIHJob25jdXMgZXJvcyBsb2JvcnRpcyBudWxsYSBtb2xlc3RpZSBtYXR0aXMgc2NlbGVyaXNxdWUgbWF4aW11cyBlZ2V0IGZlcm1lbnR1bSBvZGlvIHBoYXNlbGx1cyBub24gcHVydXMgZXN0IGVmZmljaXR1ciBsYW9yZWV0IG1hdXJpcyBwaGFyZXRyYSB2ZXN0aWJ1bHVtIGZ1c2NlIGRpY3R1bSByaXN1cyBibGFuZGl0IHF1aXMgc3VzcGVuZGlzc2UgYWxpcXVldCBuaXNpIHNvZGFsZXMgY29uc2VxdWF0IG1hZ25hIGFudGUgY29uZGltZW50dW0gbmVxdWUgYXQgbHVjdHVzIG5pYmggZmluaWJ1cyBmYWNpbGlzaXMgZGFwaWJ1cyBldGlhbSBpbnRlcmR1bSB0b3J0b3IgbGlndWxhIGNvbmd1ZSBzb2xsaWNpdHVkaW4gZXJhdCB2aXZlcnJhIGFjIHRpbmNpZHVudCBuYW0gcG9ydGEgZWxlbWVudHVtIGEgZW5pbSBldWlzbW9kIHF1YW0ganVzdG8gbGVjdHVzIGNvbW1vZG8gYXVndWUgYXJjdSBkaWduaXNzaW0gdmVsaXQgYWxpcXVhbSBpbXBlcmRpZXQgbW9sbGlzIG51bGxhbSB2b2x1dHBhdCBwb3J0dGl0b3IgdWxsYW1jb3JwZXIgcnV0cnVtIGdyYXZpZGEgY3JhcyBlbGVpZmVuZCB0dXJwaXMgZmFtZXMgcHJpbWlzIHZ1bHB1dGF0ZSBvcm5hcmUgc2FnaXR0aXMgdmVoaWN1bGEgcHJhZXNlbnQgZHVpIGZlbGlzIHZlbmVuYXRpcyB1bHRyaWNlcyBwcm9pbiBsaWJlcm8gZmV1Z2lhdCB0cmlzdGlxdWUgYWNjdW1zYW4gbWFlY2VuYXMgcG90ZW50aSB1bHRyaWNpZXMgaGFiaXRhbnQgbW9yYmkgc2VuZWN0dXMgbmV0dXMgc3VzY2lwaXQgYXVjdG9yIGN1cmFiaXR1ciBmYWNpbGlzaSBjdWJpbGlhIGN1cmFlIGhhYyBoYWJpdGFzc2UgcGxhdGVhIGRpY3R1bXN0IGxvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0IGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCBxdWlzcXVlIGZhdWNpYnVzIGV4IHNhcGllbiB2aXRhZSBwZWxsZW50ZXNxdWUgc2VtIHBsYWNlcmF0IGluIGlkIGN1cnN1cyBtaSBwcmV0aXVtIHRlbGx1cyBkdWlzIGNvbnZhbGxpcyB0ZW1wdXMgbGVvIGV1IGFlbmVhbiBzZWQgZGlhbSB1cm5hIHRlbXBvciBwdWx2aW5hciB2aXZhbXVzIGZyaW5naWxsYSBsYWN1cyBuZWMgbWV0dXMgYmliZW5kdW0gZWdlc3RhcyBpYWN1bGlzIG1hc3NhIG5pc2wgbWFsZXN1YWRhIGxhY2luaWEgaW50ZWdlciBudW5jIHBvc3VlcmUgdXQgaGVuZHJlcml0IHNlbXBlciB2ZWwgY2xhc3MgYXB0ZW50IHRhY2l0aSBzb2Npb3NxdSBhZCBsaXRvcmEgdG9ycXVlbnQgcGVyIGNvbnViaWEgbm9zdHJhIGluY2VwdG9zIGhpbWVuYWVvcyBvcmNpIHZhcml1cyBuYXRvcXVlIHBlbmF0aWJ1cyBldC4=";

	base64.populate_len_decoded(&mut witness_filler, decoded_data.len());
	base64.populate_decoded(&mut witness_filler, decoded_data);
	base64.populate_encoded(&mut witness_filler, encoded_data);

	// Get the witness vector
	circuit.populate_wire_witness(&mut witness_filler).unwrap();

	(circuit.constraint_system(), witness_filler.into_value_vec())
}

// Compute the image of the witness applied to the AND constraints
pub fn compute_bitmul_images(constraints: &[AndConstraint], witness: &ValueVec) -> [Vec<Word>; 3] {
	let (a_image, b_image, c_image) = constraints
		.iter()
		.map(|constraint| {
			let a = eval_operand(witness, &constraint.a);
			let b = eval_operand(witness, &constraint.b);
			let c = eval_operand(witness, &constraint.c);
			(a, b, c)
		})
		.multiunzip();
	[a_image, b_image, c_image]
}

// Compute the image of the witness applied to the MUL constraints
fn compute_intmul_images(constraints: &[MulConstraint], witness: &ValueVec) -> [Vec<Word>; 4] {
	let (a_image, b_image, hi_image, lo_image) = constraints
		.iter()
		.map(|constraint| {
			let a = eval_operand(witness, &constraint.a);
			let b = eval_operand(witness, &constraint.b);
			let hi = eval_operand(witness, &constraint.hi);
			let lo = eval_operand(witness, &constraint.lo);
			(a, b, hi, lo)
		})
		.multiunzip();
	[a_image, b_image, hi_image, lo_image]
}

// Evaluate the image of the witness applied to the AND or MUL constraints
// Univariate point is `r_zhat_prime`, multilinear point tensor-expanded is `r_x_prime_tensor`
fn evaluate_image<F: Field>(
	image: &[Word],
	univariate_domain: &[F],
	r_zhat_prime: F,
	r_x_prime_tensor: &[F],
) -> F {
	let l_tilde = lagrange_evals(univariate_domain, r_zhat_prime).unwrap();
	let univariate = image
		.iter()
		.map(|&word| {
			(0..64)
				.filter(|&i| (word >> i) & Word::ONE == Word::ONE)
				.map(|i| l_tilde[i as usize])
				.sum()
		})
		.collect::<Vec<_>>();
	inner_product_scalar(r_x_prime_tensor, &univariate)
}

fn bench_prove_and_verify(c: &mut Criterion) {
	use binius_field::{BinaryField128bGhash, PackedBinaryGhash1x128b, Random};
	type F = BinaryField128bGhash;
	type P = PackedBinaryGhash1x128b;
	let mut rng = StdRng::seed_from_u64(0);

	let constraint_systems_to_test = vec![
		// ("sha256", create_sha256_cs_with_witness()),
		// ("jwt_claims", create_jwt_claims_cs_with_witness()),
		// ("rs256", create_rs256_cs_with_witness()),
		// ("slice", create_slice_cs_with_witness()),
		("base64", create_base64_cs_with_witness()),
		// ("concat", create_concat_cs_with_witness()),
	];

	for (name, (cs, value_vec)) in constraint_systems_to_test {
		// Validate constraints using frontend verifier first
		if let Err(e) = verify_constraints(&cs, &value_vec) {
			panic!("Circuit {} failed constraint validation: {}", name, e);
		}

		// Sample univaraite eval point
		let r_zhat_prime_bitmul = F::random(&mut rng);
		let r_zhat_prime_intmul = F::random(&mut rng);
		// Generate univariate skip domain
		let univariate_domain = (0..WORD_SIZE_BITS as u128).map(F::new).collect::<Vec<_>>();

		// Sample multilinear eval points
		let log_bitmul_constraint_count = strict_log_2(cs.and_constraints.len()).unwrap();
		let log_intmul_constraint_count = strict_log_2(cs.mul_constraints.len()).unwrap();

		let r_x_prime_bitmul = (0..log_bitmul_constraint_count as u128)
			.map(F::new)
			.collect::<Vec<_>>();
		let r_x_prime_intmul = (0..log_intmul_constraint_count as u128)
			.map(F::new)
			.collect::<Vec<_>>();

		let r_x_prime_bitmul_tensor: Vec<F> =
			tensor_expand_scalar(&r_x_prime_bitmul, r_x_prime_bitmul.len());
		let r_x_prime_intmul_tensor: Vec<F> =
			tensor_expand_scalar(&r_x_prime_intmul, r_x_prime_intmul.len());

		// Compute bitmul evals
		let bitmul_evals = compute_bitmul_images(&cs.and_constraints, &value_vec).map(|image| {
			evaluate_image(
				&image,
				&univariate_domain,
				r_zhat_prime_bitmul,
				&r_x_prime_bitmul_tensor,
			)
		});

		// Compute intmul evals
		let intmul_evals = compute_intmul_images(&cs.mul_constraints, &value_vec).map(|image| {
			evaluate_image(
				&image,
				&univariate_domain,
				r_zhat_prime_intmul,
				&r_x_prime_intmul_tensor,
			)
		});

		let record = build_prover_constraint_system(&cs);

		let verifier_bitmul_data =
			VerifierOperatorData::new(r_x_prime_bitmul.clone(), r_zhat_prime_bitmul, bitmul_evals);
		let verifier_intmul_data =
			VerifierOperatorData::new(r_x_prime_intmul.clone(), r_zhat_prime_intmul, intmul_evals);

		let inout_n_vars = strict_log_2(
			(cs.value_vec_layout.n_const + cs.value_vec_layout.n_inout).next_power_of_two(),
		)
		.unwrap();

		// Benchmark the prover with reduced sample count for large systems
		let mut group = c.benchmark_group(name);
		group.sample_size(25);

		// Initialize tracing if enabled
		if std::env::var("BENCH_TRACE").is_ok() {
			init_bench_tracing(name);
		}

		group.bench_function("prove", |b| {
			b.iter_with_setup(
				|| record.clone(),
				|record| {
					let prover_bitmul_data = OperatorData::new(
						r_zhat_prime_bitmul,
						r_x_prime_bitmul.clone(),
						bitmul_evals.to_vec(),
					);
					let prover_intmul_data = OperatorData::new(
						r_zhat_prime_intmul,
						r_x_prime_intmul.clone(),
						intmul_evals.to_vec(),
					);

					let mut prover_transcript = ProverTranscript::<StdChallenger>::default();

					prove::<F, P, StdChallenger>(
						record,
						value_vec.combined_witness(),
						inout_n_vars,
						prover_bitmul_data,
						prover_intmul_data,
						&mut prover_transcript,
					)
					.unwrap()
				},
			)
		});

		// // Pre-run the prover to get the transcript for verifier benchmarking
		// let prover_bitmul_data =
		// 	OperatorData::new(r_zhat_prime_bitmul, r_x_prime_bitmul.clone(), bitmul_evals.to_vec());
		// let prover_intmul_data =
		// 	OperatorData::new(r_zhat_prime_intmul, r_x_prime_intmul.clone(), intmul_evals.to_vec());
		// let mut setup_prover_transcript = ProverTranscript::<StdChallenger>::default();
		// let _setup_prover_output = prove::<F, P, StdChallenger>(
		// 	record.clone(),
		// 	value_vec.combined_witness(),
		// 	inout_n_vars,
		// 	prover_bitmul_data,
		// 	prover_intmul_data,
		// 	&mut setup_prover_transcript,
		// )
		// .unwrap();
		// let setup_verifier_transcript = setup_prover_transcript.into_verifier();

		// group.bench_function("verify", |b| {
		// 	b.iter_with_setup(
		// 		|| (verifier_bitmul_data.clone(), verifier_intmul_data.clone()),
		// 		|(verifier_bitmul_data, verifier_intmul_data)| {
		// 			// Clone the pre-computed verifier transcript for each iteration
		// 			let mut verifier_transcript = setup_verifier_transcript.clone();
		// 			black_box(
		// 				verify(
		// 					cs.clone(),
		// 					verifier_bitmul_data,
		// 					verifier_intmul_data,
		// 					&mut verifier_transcript,
		// 				)
		// 				.unwrap(),
		// 			)
		// 		},
		// 	)
		// });
	}
}

criterion_group!(benches, bench_prove_and_verify);
criterion_main!(benches);
