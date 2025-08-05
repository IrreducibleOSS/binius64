//! This module tests that the NTT implementations are equivalent to a simple reference
//! implementation.

use std::iter::repeat_with;

use binius_field::{
	BinaryField, PackedBinaryGhash1x128b, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b,
	PackedField,
	packed::{get_packed_slice, set_packed_slice},
};

use super::{AdditiveNTT, DomainContext};
use crate::{
	BinarySubspace,
	ntt::{
		NeighborsLastMultiThread, NeighborsLastSingleThread,
		domain_context::{GaoMateerPreExpanded, GenericPreExpanded, TraceOneElement},
	},
};

/// Reference NTT (for "neighbors last" memory order)
struct NeighborsLastReference<DC> {
	domain_context: DC,
}

impl<DC: DomainContext> AdditiveNTT<DC::Field> for NeighborsLastReference<DC> {
	fn forward_transform<P: PackedField<Scalar = DC::Field>>(
		&self,
		data: &mut [P],
		skip_early: usize,
		skip_late: usize,
	) {
		let log_d = data.len().ilog2() as usize + P::LOG_WIDTH;

		for layer in skip_early..(log_d - skip_late) {
			let num_blocks = 1 << layer;
			let block_size_half = 1 << (log_d - layer - 1);
			for block in 0..num_blocks {
				let twiddle = self.domain_context.twiddle(layer, block);
				let block_start = block << (log_d - layer);
				for idx0 in block_start..(block_start + block_size_half) {
					let idx1 = block_size_half | idx0;
					// perform butterfly
					let mut u = get_packed_slice(data, idx0);
					let mut v = get_packed_slice(data, idx1);
					u += v * twiddle;
					v += u;
					set_packed_slice(data, idx0, u);
					set_packed_slice(data, idx1, v);
				}
			}
		}
	}

	fn domain_context(&self) -> &impl DomainContext<Field = DC::Field> {
		&self.domain_context
	}
}

fn test_equivalence<P: PackedField>(
	ntt_a: &impl AdditiveNTT<P::Scalar>,
	ntt_b: &impl AdditiveNTT<P::Scalar>,
) where
	P::Scalar: BinaryField,
{
	let log_d = 14;

	let mut rng = rand::rng();
	let mut data_a: Vec<P> = repeat_with(|| P::random(&mut rng))
		.take(1 << (log_d - P::LOG_WIDTH))
		.collect();
	let mut data_b = data_a.clone();

	for skip_early in [0, 3, 7] {
		for skip_late in [0, 3, 7] {
			ntt_a.forward_transform(&mut data_a, skip_early, skip_late);
			ntt_b.forward_transform(&mut data_b, skip_early, skip_late);
			assert_eq!(data_a, data_b)
		}
	}
}

fn test_equivalence_ntts<P: PackedField>(
	domain_context: impl DomainContext<Field = P::Scalar> + Clone + Sync,
) where
	P::Scalar: BinaryField,
{
	let ntt_ref = NeighborsLastReference {
		domain_context: domain_context.clone(),
	};
	let ntt_single = NeighborsLastSingleThread {
		domain_context: domain_context.clone(),
	};
	let ntt_multi_0 = NeighborsLastMultiThread {
		domain_context: domain_context.clone(),
		log_num_shares: 0,
	};
	let ntt_multi_1 = NeighborsLastMultiThread {
		domain_context: domain_context.clone(),
		log_num_shares: 1,
	};
	let ntt_multi_2 = NeighborsLastMultiThread {
		domain_context: domain_context.clone(),
		log_num_shares: 3,
	};

	test_equivalence::<P>(&ntt_ref, &ntt_single);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_0);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_1);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_2);
}

fn test_equivalence_ntts_domain_contexts<P: PackedField>()
where
	P::Scalar: BinaryField + TraceOneElement,
{
	let dc_1 = GaoMateerPreExpanded::<P::Scalar>::generate(20);
	test_equivalence_ntts::<P>(dc_1);

	let subspace = BinarySubspace::with_dim(20).unwrap();
	let dc_2 = GenericPreExpanded::<P::Scalar>::generate_from_subspace(&subspace);
	test_equivalence_ntts::<P>(dc_2);
}

#[test]
fn test_equivalence_ntts_domain_contexts_packings() {
	test_equivalence_ntts_domain_contexts::<PackedBinaryGhash1x128b>();
	test_equivalence_ntts_domain_contexts::<PackedBinaryGhash2x128b>();
	test_equivalence_ntts_domain_contexts::<PackedBinaryGhash4x128b>();
}
