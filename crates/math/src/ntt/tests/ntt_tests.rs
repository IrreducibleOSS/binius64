// Copyright 2024-2025 Irreducible Inc.

use std::{iter::repeat_with, ops::Range};

use binius_field::{
	AESTowerField8b, BinaryField, BinaryField8b, ByteSlicedAES8x16x16b, ByteSlicedAES16x32x8b,
	PackedBinaryField8x32b, PackedBinaryField16x32b, PackedBinaryField32x16b, PackedExtension,
	PackedField, Random, RepackedExtension,
	arch::{
		packed_8::PackedBinaryField1x8b,
		packed_16::{PackedBinaryField1x16b, PackedBinaryField2x8b},
		packed_32::PackedBinaryField2x16b,
		packed_64::{PackedBinaryField2x32b, PackedBinaryField4x16b},
	},
};
use rand::prelude::*;

use crate::ntt::{AdditiveNTT, NTTShape, SingleThreadedNTT};

/// Check that forward and inverse transformation of `math` on `data` is the same as forward and
/// inverse transformation of `reference_ntt` on `data` and that the result of the roundtrip is the
/// same as the original data.
fn check_roundtrip_with_reference<F, P>(
	reference_ntt: &impl AdditiveNTT<F>,
	ntt: &impl AdditiveNTT<F>,
	data: &[P],
	shape: NTTShape,
	cosets: Range<usize>,
	coset_bits: usize,
	skip_rounds: usize,
) where
	F: BinaryField,
	P: PackedField<Scalar = F>,
{
	let NTTShape {
		log_x,
		log_y,
		log_z,
	} = shape;

	let log_len = log_x + log_y + log_z;
	let mut orig_data = data.to_vec();

	if log_len < P::LOG_WIDTH {
		for i in 1 << log_len..P::WIDTH {
			orig_data[0].set(i, F::ZERO);
		}
	}

	let mut data_copy_impl = orig_data.clone();
	let mut data_copy_ref = orig_data.clone();

	for coset in cosets {
		ntt.forward_transform(&mut data_copy_impl, shape, coset, coset_bits, skip_rounds)
			.unwrap();
		reference_ntt
			.forward_transform(&mut data_copy_ref, shape, coset, coset_bits, skip_rounds)
			.unwrap();

		assert_eq!(&data_copy_impl, &data_copy_ref);

		ntt.inverse_transform(&mut data_copy_impl, shape, coset, coset_bits, skip_rounds)
			.unwrap();
		reference_ntt
			.inverse_transform(&mut data_copy_ref, shape, coset, coset_bits, skip_rounds)
			.unwrap();

		assert_eq!(&orig_data, &data_copy_impl);
		assert_eq!(&orig_data, &data_copy_ref);
	}
}

/// Check the all NTTs have the same behavior.
fn check_roundtrip_all_ntts<P>(
	log_domain_size: usize,
	log_data_size: usize,
	max_log_stride_batch: usize,
	max_log_coset: usize,
) where
	P: PackedField<Scalar: BinaryField>,
{
	let simple_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.into_simple_ntt();
	let single_threaded_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size).unwrap();
	let single_threaded_precompute_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.precompute_twiddles();
	let multithreaded_ntt_2 = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.multithreaded_with_max_threads(1);
	let multithreaded_ntt_4 = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.multithreaded_with_max_threads(2);
	let multithreaded_precompute_ntt_2 = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.precompute_twiddles()
		.multithreaded_with_max_threads(1);

	let mut rng = StdRng::seed_from_u64(0);
	let data = (0..1u128 << log_data_size)
		.map(|_| P::random(&mut rng))
		.collect::<Vec<_>>();

	let cosets = 0..1 << max_log_coset;
	for log_stride_batch in 0..=max_log_stride_batch {
		let log_n_b_range = if data.len() > 1 {
			let single_log_n = data.len().ilog2() as usize + P::LOG_WIDTH - log_stride_batch;
			single_log_n..single_log_n + 1
		} else {
			0..P::LOG_WIDTH - log_stride_batch
		};

		for log_n_b in log_n_b_range {
			for log_n in 0..=log_n_b {
				let log_batch = log_n_b - log_n;
				let shape = NTTShape {
					log_x: log_stride_batch,
					log_y: log_n,
					log_z: log_batch,
				};

				for skip_rounds in [0, log_n / 3, log_n / 2] {
					check_roundtrip_with_reference(
						&simple_ntt,
						&single_threaded_ntt,
						&data,
						shape,
						cosets.clone(),
						max_log_coset,
						skip_rounds,
					);
					check_roundtrip_with_reference(
						&simple_ntt,
						&single_threaded_precompute_ntt,
						&data,
						shape,
						cosets.clone(),
						max_log_coset,
						skip_rounds,
					);
					check_roundtrip_with_reference(
						&simple_ntt,
						&multithreaded_ntt_2,
						&data,
						shape,
						cosets.clone(),
						max_log_coset,
						skip_rounds,
					);
					check_roundtrip_with_reference(
						&simple_ntt,
						&multithreaded_ntt_4,
						&data,
						shape,
						cosets.clone(),
						max_log_coset,
						skip_rounds,
					);
					check_roundtrip_with_reference(
						&simple_ntt,
						&multithreaded_precompute_ntt_2,
						&data,
						shape,
						cosets.clone(),
						max_log_coset,
						skip_rounds,
					);
				}
			}
		}
	}
}

#[test]
fn tests_roundtrip_packed_1() {
	check_roundtrip_all_ntts::<BinaryField8b>(8, 6, 4, 2);
}

#[test]
fn tests_roundtrip_packed_2() {
	check_roundtrip_all_ntts::<PackedBinaryField2x8b>(8, 6, 4, 1);
}

#[test]
fn tests_roundtrip_packed_4() {
	check_roundtrip_all_ntts::<PackedBinaryField2x8b>(8, 6, 4, 0);
}

#[test]
fn tests_field_256_bits() {
	check_roundtrip_all_ntts::<PackedBinaryField8x32b>(12, 8, 4, 1);
}

#[test]
fn tests_field_512_bits() {
	check_roundtrip_all_ntts::<PackedBinaryField16x32b>(13, 6, 4, 1);
}

#[test]
fn tests_3d_bytesliced_field_128_bits() {
	check_roundtrip_all_ntts::<ByteSlicedAES8x16x16b>(14, 6, 4, 1);
}

#[test]
fn test_sub_packing_width() {
	check_roundtrip_all_ntts::<PackedBinaryField32x16b>(12, 0, 2, 1);
}

#[test]
fn test_3d_bytesliced_sub_packing_width() {
	check_roundtrip_all_ntts::<ByteSlicedAES8x16x16b>(12, 0, 2, 1);
}

#[test]
fn test_3d_bytesliced_larger_than_domain() {
	check_roundtrip_all_ntts::<ByteSlicedAES16x32x8b>(8, 0, 0, 0);
}

fn check_packed_extension_roundtrip_with_reference<F, PE>(
	reference_ntt: &impl AdditiveNTT<F>,
	ntt: &impl AdditiveNTT<F>,
	data: &mut [PE],
	cosets: Range<usize>,
	coset_bits: usize,
) where
	F: BinaryField,
	PE: PackedExtension<F>,
{
	let data_copy = data.to_vec();
	let mut data_copy_2 = data.to_vec();

	for coset in cosets {
		let log_n = data.len().ilog2() as usize + PE::LOG_WIDTH;

		let shape = NTTShape {
			log_y: log_n,
			..Default::default()
		};

		ntt.forward_transform_ext(data, shape, coset, coset_bits, 0)
			.unwrap();
		reference_ntt
			.forward_transform_ext(&mut data_copy_2, shape, coset, coset_bits, 0)
			.unwrap();

		assert_eq!(data, &data_copy_2);

		ntt.inverse_transform_ext(data, shape, coset, coset_bits, 0)
			.unwrap();
		reference_ntt
			.inverse_transform_ext(&mut data_copy_2, shape, coset, coset_bits, 0)
			.unwrap();

		assert_eq!(data, &data_copy);
		assert_eq!(data, &data_copy_2);
	}
}

fn check_packed_extension_roundtrip_all_ntts<P, PE>(
	log_domain_size: usize,
	log_data_size: usize,
	max_log_coset: usize,
) where
	P: PackedField<Scalar: BinaryField>,
	PE: RepackedExtension<P>,
{
	let simple_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.into_simple_ntt();
	let single_threaded_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size).unwrap();
	let single_threaded_precompute_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.precompute_twiddles();
	let multithreaded_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.multithreaded();
	let multithreaded_precompute_ntt = SingleThreadedNTT::<P::Scalar>::new(log_domain_size)
		.unwrap()
		.precompute_twiddles()
		.multithreaded();

	let mut rng = StdRng::seed_from_u64(0);
	let mut data = repeat_with(|| PE::random(&mut rng))
		.take(1 << log_data_size)
		.collect::<Vec<_>>();

	let cosets = 0..1 << max_log_coset;

	check_packed_extension_roundtrip_with_reference(
		&simple_ntt,
		&single_threaded_ntt,
		&mut data,
		cosets.clone(),
		max_log_coset,
	);
	check_packed_extension_roundtrip_with_reference(
		&simple_ntt,
		&single_threaded_precompute_ntt,
		&mut data,
		cosets.clone(),
		max_log_coset,
	);
	check_packed_extension_roundtrip_with_reference(
		&simple_ntt,
		&multithreaded_ntt,
		&mut data,
		cosets.clone(),
		max_log_coset,
	);
	check_packed_extension_roundtrip_with_reference(
		&simple_ntt,
		&multithreaded_precompute_ntt,
		&mut data,
		cosets.clone(),
		max_log_coset,
	);
}

#[test]
fn tests_packed_extension_roundtrip_packed_single_value() {
	check_packed_extension_roundtrip_all_ntts::<PackedBinaryField1x8b, PackedBinaryField1x8b>(
		8, 6, 2,
	);
	check_packed_extension_roundtrip_all_ntts::<PackedBinaryField1x16b, PackedBinaryField1x16b>(
		9, 6, 2,
	);
}

#[test]
fn tests_packed_extension_roundtrip_packed_2_packed() {
	check_packed_extension_roundtrip_all_ntts::<PackedBinaryField2x8b, PackedBinaryField2x8b>(
		8, 6, 1,
	);
	check_packed_extension_roundtrip_all_ntts::<PackedBinaryField2x16b, PackedBinaryField2x16b>(
		9, 6, 2,
	);
}

#[test]
fn tests_packed_extension_roundtrip_packed_extension() {
	check_packed_extension_roundtrip_all_ntts::<PackedBinaryField4x16b, PackedBinaryField2x32b>(
		8, 6, 1,
	);
}

#[test]
fn tests_packed_extension_roundtrip_message_size_1() {
	check_packed_extension_roundtrip_all_ntts::<PackedBinaryField2x32b, PackedBinaryField2x32b>(
		8, 0, 1,
	);
	check_packed_extension_roundtrip_all_ntts::<PackedBinaryField4x16b, PackedBinaryField4x16b>(
		8, 0, 1,
	);
}

/// Check that NTT transformations give isomorphic results for isomorphic fields.
fn check_ntt_with_transform<P1, P2>(
	ntt_binary: &impl AdditiveNTT<P1::Scalar>,
	ntt_aes_1: &impl AdditiveNTT<P2::Scalar>,
	ntt_aes_2: &impl AdditiveNTT<P2::Scalar>,
	data_size: usize,
) where
	P1: PackedField<Scalar: BinaryField>,
	P2: PackedField<Scalar: BinaryField + From<P1::Scalar>> + From<P1>,
{
	let mut rng = StdRng::seed_from_u64(0);

	let data: Vec<_> = (0..data_size)
		.map(|_| P1::Scalar::random(&mut rng))
		.collect();
	let data_as_aes: Vec<_> = data.iter().map(|x| P2::Scalar::from(*x)).collect();

	let coset_bits = 2;
	for coset in 0..1 << coset_bits {
		let mut result_bin = data.clone();
		let mut result_aes = data_as_aes.clone();
		let mut result_aes_cob = data_as_aes.clone();

		let log_n = data_size.ilog2() as usize + P1::LOG_WIDTH;
		let shape = NTTShape {
			log_y: log_n,
			..Default::default()
		};

		ntt_binary
			.forward_transform(&mut result_bin, shape, coset, coset_bits, 0)
			.unwrap();
		ntt_aes_1
			.forward_transform(&mut result_aes, shape, coset, coset_bits, 0)
			.unwrap();
		ntt_aes_2
			.forward_transform(&mut result_aes_cob, shape, coset, coset_bits, 0)
			.unwrap();

		let result_bin_to_aes: Vec<_> = result_bin.iter().map(|x| P2::Scalar::from(*x)).collect();

		assert_eq!(result_bin_to_aes, result_aes_cob);
		assert_ne!(result_bin_to_aes, result_aes);

		ntt_binary
			.inverse_transform(&mut result_bin, shape, coset, coset_bits, 0)
			.unwrap();
		ntt_aes_1
			.inverse_transform(&mut result_aes, shape, coset, coset_bits, 0)
			.unwrap();
		ntt_aes_2
			.inverse_transform(&mut result_aes_cob, shape, coset, coset_bits, 0)
			.unwrap();

		let result_bin_to_aes: Vec<_> = result_bin.iter().map(|x| P2::Scalar::from(*x)).collect();

		assert_eq!(result_bin_to_aes, result_aes_cob);
	}
}

#[test]
fn test_transform_single_thread_on_the_fly() {
	check_ntt_with_transform::<BinaryField8b, AESTowerField8b>(
		&SingleThreadedNTT::<BinaryField8b>::new(8).unwrap(),
		&SingleThreadedNTT::<AESTowerField8b>::new(8).unwrap(),
		&SingleThreadedNTT::<AESTowerField8b, _>::with_domain_field::<BinaryField8b>(8).unwrap(),
		64,
	)
}

#[test]
fn test_transform_single_thread_precompute() {
	check_ntt_with_transform::<BinaryField8b, AESTowerField8b>(
		&SingleThreadedNTT::<BinaryField8b>::new(8).unwrap(),
		&SingleThreadedNTT::<AESTowerField8b>::new(8)
			.unwrap()
			.precompute_twiddles(),
		&SingleThreadedNTT::<AESTowerField8b, _>::with_domain_field::<BinaryField8b>(8)
			.unwrap()
			.precompute_twiddles(),
		64,
	)
}

#[test]
fn test_transform_multithread_on_the_fly() {
	check_ntt_with_transform::<BinaryField8b, AESTowerField8b>(
		&SingleThreadedNTT::<BinaryField8b>::new(8).unwrap(),
		&SingleThreadedNTT::<AESTowerField8b>::new(8)
			.unwrap()
			.multithreaded(),
		&SingleThreadedNTT::<AESTowerField8b, _>::with_domain_field::<BinaryField8b>(8)
			.unwrap()
			.multithreaded(),
		64,
	)
}

#[test]
fn test_transform_multithread_precompute() {
	check_ntt_with_transform::<BinaryField8b, AESTowerField8b>(
		&SingleThreadedNTT::<BinaryField8b>::new(8).unwrap(),
		&SingleThreadedNTT::<AESTowerField8b>::new(8)
			.unwrap()
			.precompute_twiddles()
			.multithreaded(),
		&SingleThreadedNTT::<AESTowerField8b, _>::with_domain_field::<BinaryField8b>(8)
			.unwrap()
			.precompute_twiddles()
			.multithreaded(),
		64,
	)
}
