// Copyright 2024-2025 Irreducible Inc.
use crate::{
	AESTowerField8b, PackedField,
	tower_levels::{TowerLevel, TowerLevelWithArithOps},
	underlier::WithUnderlier,
};

#[inline(always)]
pub fn mul<P: PackedField<Scalar = AESTowerField8b>, Level: TowerLevel>(
	field_element_a: &Level::Data<P>,
	field_element_b: &Level::Data<P>,
	destination: &mut Level::Data<P>,
) {
	let base_alpha = P::broadcast(AESTowerField8b::from_underlier(0xd3));
	mul_main::<true, P, Level>(field_element_a, field_element_b, destination, base_alpha);
}

#[inline(always)]
pub fn mul_alpha<
	const WRITING_TO_ZEROS: bool,
	P: PackedField<Scalar = AESTowerField8b>,
	Level: TowerLevel,
>(
	field_element: &Level::Data<P>,
	destination: &mut Level::Data<P>,
	base_alpha: P,
) {
	if Level::WIDTH == 1 {
		if WRITING_TO_ZEROS {
			destination.as_mut()[0] = field_element[0] * base_alpha;
		} else {
			destination.as_mut()[0] += field_element[0] * base_alpha;
		}
		return;
	}

	let (a0, a1) = Level::split(field_element);

	let (result0, result1) = Level::split_mut(destination);

	if WRITING_TO_ZEROS {
		// Copy a0 into upper half
		Level::Base::copy_into(a0, result1);

		// Copy a1 into lower half
		Level::Base::copy_into(a1, result0);
	} else {
		// Copy a0 into upper half
		Level::Base::add_into(a0, result1);

		// Copy a1 into lower half
		Level::Base::add_into(a1, result0);
	}
	// Copy alpha*a1 into upper half
	mul_alpha::<false, P, Level::Base>(a1, result1, base_alpha);
}

#[inline(always)]
pub fn mul_main<
	const WRITING_TO_ZEROS: bool,
	P: PackedField<Scalar = AESTowerField8b>,
	Level: TowerLevel,
>(
	field_element_a: &Level::Data<P>,
	field_element_b: &Level::Data<P>,
	destination: &mut Level::Data<P>,
	base_alpha: P,
) {
	if Level::WIDTH == 1 {
		if WRITING_TO_ZEROS {
			destination.as_mut()[0] = field_element_a[0] * field_element_b[0];
		} else {
			destination.as_mut()[0] += field_element_a[0] * field_element_b[0];
		}
		return;
	}

	let (a0, a1) = Level::split(field_element_a);

	let (b0, b1) = Level::split(field_element_b);

	let (result0, result1) = Level::split_mut(destination);

	let xored_halves_a = Level::Base::sum(a0, a1);

	let xored_halves_b = Level::Base::sum(b0, b1);

	let mut z2_z0 = <<Level as TowerLevel>::Base as TowerLevel>::default();

	// z2_z0 = z2
	mul_main::<true, P, Level::Base>(a1, b1, &mut z2_z0, base_alpha);

	// result1 = z2 * alpha
	mul_alpha::<WRITING_TO_ZEROS, P, Level::Base>(&z2_z0, result1, base_alpha);

	// z2_z0 = z2 + z0
	mul_main::<false, P, Level::Base>(a0, b0, &mut z2_z0, base_alpha);

	// result1 = z1 + z2 * alpha
	mul_main::<false, P, Level::Base>(&xored_halves_a, &xored_halves_b, result1, base_alpha);

	// result1 = z2+ z0+ z1 + z2 * alpha
	Level::Base::add_into(&z2_z0, result1);

	if WRITING_TO_ZEROS {
		Level::Base::copy_into(&z2_z0, result0);
	} else {
		Level::Base::add_into(&z2_z0, result0);
	}
}
