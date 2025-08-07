//! This module tests that the NTT implementations are equivalent to a simple reference
//! implementation.

use std::iter::repeat_with;

use binius_field::{
	BinaryField, PackedBinaryGhash1x128b, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b,
	PackedField,
};

use super::{AdditiveNTT, DomainContext};
use crate::{
	BinarySubspace,
	ntt::{
		NeighborsLastMultiThread, NeighborsLastReference, NeighborsLastSingleThread,
		domain_context::{GaoMateerPreExpanded, GenericPreExpanded, TraceOneElement},
	},
};

fn test_equivalence<P: PackedField>(
	ntt_a: &impl AdditiveNTT<Field = P::Scalar>,
	ntt_b: &impl AdditiveNTT<Field = P::Scalar>,
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
	let ntt_single: NeighborsLastSingleThread<_> = NeighborsLastSingleThread {
		domain_context: domain_context.clone(),
	};
	let ntt_multi_0: NeighborsLastMultiThread<_> = NeighborsLastMultiThread {
		domain_context: domain_context.clone(),
		log_num_shares: 0,
	};
	let ntt_multi_1: NeighborsLastMultiThread<_> = NeighborsLastMultiThread {
		domain_context: domain_context.clone(),
		log_num_shares: 1,
	};
	let ntt_multi_3: NeighborsLastMultiThread<_> = NeighborsLastMultiThread {
		domain_context: domain_context.clone(),
		log_num_shares: 3,
	};

	test_equivalence::<P>(&ntt_ref, &ntt_single);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_0);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_1);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_3);
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

fn test_composition<P: PackedField>()
where
	P::Scalar: BinaryField,
{
	let log_d = 7;
	let mut rng = rand::rng();
	let data_orig: Vec<P> = repeat_with(|| P::random(&mut rng))
		.take(1 << (log_d - P::LOG_WIDTH))
		.collect();
	let mut data = data_orig.clone();

	let subspace = BinarySubspace::<P::Scalar>::with_dim(10).unwrap();
	let domain_context = GenericPreExpanded::generate_from_subspace(&subspace);
	let ntt = NeighborsLastReference { domain_context };
	for skip_early in [0, 1, 2] {
		for skip_late in [0, 1, 2] {
			ntt.forward_transform(&mut data, skip_early, skip_late);
			ntt.inverse_transform(&mut data, skip_early, skip_late);
			assert_eq!(data, data_orig);
		}
	}
}

#[test]
fn test_composition_packings() {
	test_composition::<PackedBinaryGhash1x128b>();
	test_composition::<PackedBinaryGhash2x128b>();
	test_composition::<PackedBinaryGhash4x128b>();
}
