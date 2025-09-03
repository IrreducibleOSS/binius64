// Copyright 2025 Irreducible Inc.

use binius_field::BinaryField128bGhash as Ghash;
use binius_utils::{DeserializeBytes, SerializeBytes};
use digest::Output;

use super::{constants::M, permutation::permutation};
use crate::hash::{
	CompressionFunction, PseudoCompressionFunction, vision_4::digest::VisionHasherDigest,
};

/// Vision pseudo-compression function for 2-to-1 compression.
///
///
/// This applies the Vision permutation to the combined inputs, adds back the original
/// input state, and truncates the result to maintain the output size. This construction
/// is collision-resistant thus implementing the `CompressionFunction` trait.
/// This is the well known technique of implementing a collision resistant hash function
/// `h` by putting the input through a cryptographic permutation `p`, and then adding the input
/// to the result before truncating: `h(x) = Trunc(p(x) ⊕ x)`
#[derive(Clone, Debug, Default)]
pub struct VisionCompression;

impl PseudoCompressionFunction<Output<VisionHasherDigest>, 2> for VisionCompression {
	fn compress(&self, input: [Output<VisionHasherDigest>; 2]) -> Output<VisionHasherDigest> {
		// Step 1: Deserialize each 32-byte input into 2 Ghash elements
		let mut state: [Ghash; M] = [
			Ghash::deserialize(&input[0][0..16]).expect("16 bytes fits in Ghash"),
			Ghash::deserialize(&input[0][16..32]).expect("16 bytes fits in Ghash"),
			Ghash::deserialize(&input[1][0..16]).expect("16 bytes fits in Ghash"),
			Ghash::deserialize(&input[1][16..32]).expect("16 bytes fits in Ghash"),
		];

		// Step 2: Copy original first 2 state elements
		let original_first = state[0];
		let original_second = state[1];

		// Step 3: Apply Vision permutation
		permutation(&mut state);

		// Step 4: Add original first 2 elements to permuted result
		state[0] += original_first;
		state[1] += original_second;

		// Step 5: Serialize first 2 elements (left half) back to 32 bytes
		let mut output = Output::<VisionHasherDigest>::default();
		let (left, right) = output.as_mut_slice().split_at_mut(16);
		state[0].serialize(left).expect("fits in 16 bytes");
		state[1].serialize(right).expect("fits in 16 bytes");
		// Note: state[2] and state[3] are discarded (right half truncated)

		output
	}
}

impl CompressionFunction<Output<VisionHasherDigest>, 2> for VisionCompression {}
