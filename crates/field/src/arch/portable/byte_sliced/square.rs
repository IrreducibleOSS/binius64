// Copyright 2024-2025 Irreducible Inc.
use super::multiply::mul_alpha;
use crate::{
	AESTowerField8b, PackedField,
	tower_levels::{TowerLevel, TowerLevelWithArithOps},
	underlier::WithUnderlier,
};

#[inline(always)]
pub fn square<P: PackedField<Scalar = AESTowerField8b>, Level: TowerLevel>(
	field_element: &Level::Data<P>,
	destination: &mut Level::Data<P>,
) {
	let base_alpha = P::broadcast(AESTowerField8b::from_underlier(0xd3));
	square_main::<true, P, Level>(field_element, destination, base_alpha);
}

#[inline(always)]
pub fn square_main<
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
			destination.as_mut()[0] = field_element[0].square();
		} else {
			destination.as_mut()[0] += field_element[0].square();
		}
		return;
	}

	let (a0, a1) = Level::split(field_element);

	let (result0, result1) = Level::split_mut(destination);
	let mut a1_squared = <<Level as TowerLevel>::Base as TowerLevel>::default();

	square_main::<true, P, Level::Base>(a1, &mut a1_squared, base_alpha);

	mul_alpha::<WRITING_TO_ZEROS, P, Level::Base>(&a1_squared, result1, base_alpha);

	square_main::<WRITING_TO_ZEROS, P, Level::Base>(a0, result0, base_alpha);

	Level::Base::add_into(&a1_squared, result0);
}
