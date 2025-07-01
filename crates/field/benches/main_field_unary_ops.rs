// Copyright 2025 Irreducible Inc.

mod packed_field_utils;

use binius_field::{
	AESTowerField8b, AESTowerField16b, AESTowerField32b, AESTowerField64b, AESTowerField128b,
	BinaryField1b, BinaryField8b, BinaryField16b, BinaryField32b, BinaryField64b, BinaryField128b,
	BinaryField128bPolyval, PackedField,
	arch::{OptimalUnderlier, OptimalUnderlierByteSliced},
	as_packed_field::PackedType,
};
use criterion::criterion_main;
use packed_field_utils::benchmark_packed_operation;

type OptimalPackedFP1b = PackedType<OptimalUnderlier, BinaryField1b>;
type OptimalPackedFP8b = PackedType<OptimalUnderlier, BinaryField8b>;
type OptimalPackedFP16b = PackedType<OptimalUnderlier, BinaryField16b>;
type OptimalPackedFP32b = PackedType<OptimalUnderlier, BinaryField32b>;
type OptimalPackedFP64b = PackedType<OptimalUnderlier, BinaryField64b>;
type OptimalPackedFP128b = PackedType<OptimalUnderlier, BinaryField128b>;

type OptimalPackedAES8b = PackedType<OptimalUnderlier, AESTowerField8b>;
type OptimalPackedAES16b = PackedType<OptimalUnderlier, AESTowerField16b>;
type OptimalPackedAES32b = PackedType<OptimalUnderlier, AESTowerField32b>;
type OptimalPackedAES64b = PackedType<OptimalUnderlier, AESTowerField64b>;
type OptimalPackedAES128b = PackedType<OptimalUnderlier, AESTowerField128b>;

type OptimalPackedPolyval128b = PackedType<OptimalUnderlier, BinaryField128bPolyval>;

type OptimalByteSliced1b = PackedType<OptimalUnderlierByteSliced, BinaryField1b>;
type OptimalByteSlicedAES8b = PackedType<OptimalUnderlierByteSliced, AESTowerField8b>;
type OptimalByteSlicedAES16b = PackedType<OptimalUnderlierByteSliced, AESTowerField16b>;
type OptimalByteSlicedAES32b = PackedType<OptimalUnderlierByteSliced, AESTowerField32b>;
type OptimalByteSlicedAES64b = PackedType<OptimalUnderlierByteSliced, AESTowerField64b>;
type OptimalByteSlicedAES128b = PackedType<OptimalUnderlierByteSliced, AESTowerField128b>;

fn invert<T: PackedField>(val: T) -> T {
	val.invert_or_zero()
}

fn square<T: PackedField>(val: T) -> T {
	val.square()
}

benchmark_packed_operation!(
	op_name @ main_unary_ops,
	bench_type @ unary_op,
	strategies @ (
		(main_invert, PackedField, invert),
		(main_square, PackedField, square),
	),
	packed_fields @ [
		// Fan-Paar Packed Fields
		OptimalPackedFP1b
		OptimalPackedFP8b
		OptimalPackedFP16b
		OptimalPackedFP32b
		OptimalPackedFP64b
		OptimalPackedFP128b

		// AES-Tower Packed Fields
		OptimalPackedAES8b
		OptimalPackedAES16b
		OptimalPackedAES32b
		OptimalPackedAES64b
		OptimalPackedAES128b

		// Polyval field
		OptimalPackedPolyval128b

		// Byte-sliced fields
		OptimalByteSliced1b
		OptimalByteSlicedAES8b
		OptimalByteSlicedAES16b
		OptimalByteSlicedAES32b
		OptimalByteSlicedAES64b
		OptimalByteSlicedAES128b
	]
);

criterion_main!(main_unary_ops);
