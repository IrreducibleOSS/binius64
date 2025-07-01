// Copyright 2024-2025 Irreducible Inc.
use super::{
	multiply::{mul_alpha, mul_main},
	square::square_main,
};
use crate::{
	AESTowerField8b, PackedField,
	tower_levels::{TowerLevel, TowerLevelWithArithOps},
	underlier::WithUnderlier,
};

#[inline(always)]
pub fn invert_or_zero<P: PackedField<Scalar = AESTowerField8b>, Level: TowerLevel>(
	field_element: &Level::Data<P>,
	destination: &mut Level::Data<P>,
) {
	let base_alpha = P::broadcast(AESTowerField8b::from_underlier(0xd3));

	inv_main::<P, Level>(field_element, destination, base_alpha);
}

#[inline(always)]
fn inv_main<P: PackedField<Scalar = AESTowerField8b>, Level: TowerLevel>(
	field_element: &Level::Data<P>,
	destination: &mut Level::Data<P>,
	base_alpha: P,
) {
	if Level::WIDTH == 1 {
		destination.as_mut()[0] = field_element.as_ref()[0].invert_or_zero();
		return;
	}

	let (a0, a1) = Level::split(field_element);

	let (result0, result1) = Level::split_mut(destination);

	let mut intermediate = <<Level as TowerLevel>::Base as TowerLevel>::default();

	// intermediate = subfield_alpha*a1
	mul_alpha::<true, P, Level::Base>(a1, &mut intermediate, base_alpha);

	// intermediate = a0 + subfield_alpha*a1
	Level::Base::add_into(a0, &mut intermediate);

	let mut delta = <<Level as TowerLevel>::Base as TowerLevel>::default();

	// delta = intermediate * a0
	mul_main::<true, P, Level::Base>(&intermediate, a0, &mut delta, base_alpha);

	// delta = intermediate * a0 + a1^2
	square_main::<false, P, Level::Base>(a1, &mut delta, base_alpha);

	let mut delta_inv = <<Level as TowerLevel>::Base as TowerLevel>::default();

	// delta_inv = 1/delta
	inv_main::<P, Level::Base>(&delta, &mut delta_inv, base_alpha);

	// result0 = delta_inv*intermediate
	mul_main::<true, P, Level::Base>(&delta_inv, &intermediate, result0, base_alpha);

	// result1 = delta_inv*intermediate
	mul_main::<true, P, Level::Base>(&delta_inv, a1, result1, base_alpha);
}
