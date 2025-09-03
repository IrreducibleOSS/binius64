// Copyright 2025 Irreducible Inc.

use std::{array, fmt::Debug, mem::MaybeUninit};

use binius_field::{BinaryField128bGhash as Ghash, Field};
use binius_utils::{
	DeserializeBytes, SerializeBytes,
	rayon::{
		iter::{IndexedParallelIterator, ParallelIterator},
		slice::ParallelSliceMut,
	},
};
use binius_verifier::hash::vision_4::{
	compression::VisionCompression, constants::M, digest::VisionHasherDigest,
};
use digest::Output;

use super::{
	super::parallel_compression::ParallelPseudoCompression, permutation::batch_permutation,
};

/// Parallel Vision compression with N parallel compressions using rayon.
///
/// Processes N compression pairs simultaneously using parallel Vision permutation
/// and multithreading for optimal performance.
const N: usize = 128;
const MN: usize = N * M;

#[derive(Clone, Debug, Default)]
pub struct VisionParallelCompression {
	compression: VisionCompression,
}

impl VisionParallelCompression {
	pub fn new() -> Self {
		Self {
			compression: VisionCompression,
		}
	}
}

impl ParallelPseudoCompression<Output<VisionHasherDigest>, 2> for VisionParallelCompression {
	type Compression = VisionCompression;

	fn compression(&self) -> &Self::Compression {
		&self.compression
	}

	#[tracing::instrument(
		"VisionParallelCompression::parallel_compress",
		skip_all,
		level = "info"
	)]
	fn parallel_compress(
		&self,
		inputs: &[Output<VisionHasherDigest>],
		out: &mut [MaybeUninit<Output<VisionHasherDigest>>],
	) {
		assert_eq!(inputs.len(), 2 * out.len(), "Input length must be 2 * output length");

		// Process N chunks in parallel using Rayon
		out.par_chunks_exact_mut(N)
			.enumerate()
			.for_each(|(i, output_chunk)| {
				let start_idx = i * N * 2;
				let input_chunk = &inputs[start_idx..start_idx + N * 2];
				let mut scratchpad = vec![Ghash::ZERO; 2 * MN];
				self.compress_batch_parallel(input_chunk, output_chunk, &mut scratchpad);
			});

		// Handle remaining pairs using batched processing
		let remainder_inputs = inputs.chunks_exact(N * 2).remainder();
		let remainder_outputs = out.chunks_exact_mut(N).into_remainder();

		if !remainder_outputs.is_empty() {
			// Pad remainders to full batch size for SIMD processing
			let mut padded_inputs = vec![Output::<VisionHasherDigest>::default(); N * 2];
			let mut padded_outputs = vec![MaybeUninit::uninit(); N];

			// Copy actual remainder inputs
			for (i, &input) in remainder_inputs.iter().enumerate() {
				padded_inputs[i] = input;
			}

			// Process full batch (including padding)
			let mut scratchpad = vec![Ghash::ZERO; 2 * MN];
			self.compress_batch_parallel(&padded_inputs, &mut padded_outputs, &mut scratchpad);

			// Copy only the actual results back
			for (output, padded) in remainder_outputs.iter_mut().zip(padded_outputs) {
				output.write(unsafe { padded.assume_init() });
			}
		}
	}
}

impl VisionParallelCompression {
	/// Compress exactly N pairs using parallel permutation.
	#[tracing::instrument(
		"VisionParallelCompression::compress_batch_parallel",
		skip_all,
		level = "info"
	)]
	#[inline]
	fn compress_batch_parallel(
		&self,
		inputs: &[Output<VisionHasherDigest>],
		out: &mut [MaybeUninit<Output<VisionHasherDigest>>],
		scratchpad: &mut [Ghash],
	) {
		assert_eq!(out.len(), N, "Must process exactly {N} pairs");
		assert_eq!(inputs.len(), 2 * N, "Must have 2*N inputs");

		// Step 1: Deserialize inputs into flattened state array
		let mut states = [Ghash::ZERO; MN];
		for i in 0..N {
			let input0 = &inputs[i * 2];
			let input1 = &inputs[i * 2 + 1];

			// Deserialize each 32-byte input into 2 Ghash elements
			states[i * M] = Ghash::deserialize(&input0[0..16]).expect("16 bytes fits in Ghash");
			states[i * M + 1] =
				Ghash::deserialize(&input0[16..32]).expect("16 bytes fits in Ghash");
			states[i * M + 2] = Ghash::deserialize(&input1[0..16]).expect("16 bytes fits in Ghash");
			states[i * M + 3] =
				Ghash::deserialize(&input1[16..32]).expect("16 bytes fits in Ghash");
		}

		// Step 2: Copy original first 2 elements for each state
		let originals: [_; N] = array::from_fn(|i| (states[i * M], states[i * M + 1]));

		// Step 3: Apply parallel permutation to all states
		batch_permutation::<N, MN>(&mut states, scratchpad);

		// Step 4: Add original elements back and serialize outputs
		for i in 0..N {
			states[i * M] += originals[i].0;
			states[i * M + 1] += originals[i].1;

			let mut output = Output::<VisionHasherDigest>::default();
			let (left, right) = output.as_mut_slice().split_at_mut(16);
			states[i * M].serialize(left).expect("fits in 16 bytes");
			states[i * M + 1]
				.serialize(right)
				.expect("fits in 16 bytes");
			out[i].write(output);
		}
	}
}

#[cfg(test)]
mod tests {
	use std::array;

	use binius_verifier::hash::PseudoCompressionFunction;
	use digest::Digest;

	use super::*;

	#[test]
	fn test_parallel_vs_sequential() {
		let parallel = VisionParallelCompression::default();
		let sequential = &parallel.compression;

		// Create test inputs (4 inputs = 2 pairs)
		let inputs = [
			VisionHasherDigest::new().finalize(), // input 0 (pair 0, element 0)
			{
				let mut hasher = VisionHasherDigest::new();
				hasher.update(b"first");
				hasher.finalize()
			}, // input 1 (pair 0, element 1)
			{
				let mut hasher = VisionHasherDigest::new();
				hasher.update(b"second");
				hasher.finalize()
			}, // input 2 (pair 1, element 0)
			{
				let mut hasher = VisionHasherDigest::new();
				hasher.update(b"third");
				hasher.finalize()
			}, // input 3 (pair 1, element 1)
		];

		// Compute sequential results
		let sequential_results = [
			sequential.compress([inputs[0], inputs[1]]),
			sequential.compress([inputs[2], inputs[3]]),
		];

		// Compute parallel results
		let mut parallel_outputs = [MaybeUninit::uninit(); 2];
		parallel.parallel_compress(&inputs, &mut parallel_outputs);
		let parallel_results: [_; 2] =
			array::from_fn(|i| unsafe { parallel_outputs[i].assume_init() });

		// Compare
		for i in 0..2 {
			assert_eq!(sequential_results[i], parallel_results[i], "Mismatch at index {i}");
		}
	}
}
