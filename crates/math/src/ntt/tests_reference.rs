//! This module tests that the NTT implementations are equivalent to a simple reference
//! implementation.

use binius_field::{
	BinaryField, PackedBinaryGhash1x128b, PackedBinaryGhash2x128b, PackedBinaryGhash4x128b,
	PackedField,
};
use rand::prelude::*;

use super::{AdditiveNTT, DomainContext};
use crate::test_utils::random_field_buffer;
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
	let log_d = 8;

	let mut rng = StdRng::seed_from_u64(0);
	let mut data_a = random_field_buffer::<P>(&mut rng, log_d);
	let mut data_b = data_a.clone();

	for skip_early in [0, 2, 4] {
		for skip_late in [0, 2, 4] {
			ntt_a.forward_transform(data_a.to_mut(), skip_early, skip_late);
			ntt_b.forward_transform(data_b.to_mut(), skip_early, skip_late);
			assert_eq!(data_a, data_b)
		}
	}
}

fn test_equivalence_ntts<P: PackedField>(
	domain_context: &(impl DomainContext<Field = P::Scalar> + Sync),
) where
	P::Scalar: BinaryField,
{
	let ntt_ref = NeighborsLastReference { domain_context };
	let ntt_single_2: NeighborsLastSingleThread<_, 2> =
		NeighborsLastSingleThread { domain_context };
	let ntt_single_6: NeighborsLastSingleThread<_, 6> =
		NeighborsLastSingleThread { domain_context };
	let ntt_multi_0: NeighborsLastMultiThread<_> = NeighborsLastMultiThread {
		domain_context,
		log_num_shares: 0,
	};
	let ntt_multi_1: NeighborsLastMultiThread<_> = NeighborsLastMultiThread {
		domain_context,
		log_num_shares: 1,
	};
	let ntt_multi_2: NeighborsLastMultiThread<_> = NeighborsLastMultiThread {
		domain_context,
		log_num_shares: 2,
	};
	let ntt_multi_1000: NeighborsLastMultiThread<_> = NeighborsLastMultiThread {
		domain_context,
		log_num_shares: 1000,
	};

	test_equivalence::<P>(&ntt_ref, &ntt_single_2);
	test_equivalence::<P>(&ntt_ref, &ntt_single_6);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_0);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_1);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_2);
	test_equivalence::<P>(&ntt_ref, &ntt_multi_1000);
}

fn test_equivalence_ntts_domain_contexts<P: PackedField>()
where
	P::Scalar: BinaryField + TraceOneElement,
{
	let dc_1 = GaoMateerPreExpanded::<P::Scalar>::generate(10);
	test_equivalence_ntts::<P>(&dc_1);

	let subspace = BinarySubspace::with_dim(10).unwrap();
	let dc_2 = GenericPreExpanded::<P::Scalar>::generate_from_subspace(&subspace);
	test_equivalence_ntts::<P>(&dc_2);
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
	let mut rng = StdRng::seed_from_u64(0);
	let data_orig = random_field_buffer::<P>(&mut rng, log_d);
	let mut data = data_orig.clone();

	let subspace = BinarySubspace::<P::Scalar>::with_dim(10).unwrap();
	let domain_context = GenericPreExpanded::generate_from_subspace(&subspace);
	let ntt = NeighborsLastReference { domain_context };
	for skip_early in [0, 1, 2] {
		for skip_late in [0, 1, 2] {
			ntt.forward_transform(data.to_mut(), skip_early, skip_late);
			ntt.inverse_transform(data.to_mut(), skip_early, skip_late);
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
