// Copyright 2024-2025 Irreducible Inc.

use std::ops::Deref;

use binius_field::{ExtensionField, Field, PackedField};
use binius_utils::rayon::prelude::*;

use crate::FieldBuffer;

#[inline]
pub fn inner_product<F: Field>(
	a: impl IntoIterator<Item = F>,
	b: impl IntoIterator<Item = F>,
) -> F {
	inner_product_subfield(a, b)
}

#[inline]
pub fn inner_product_subfield<F, FSub>(
	a: impl IntoIterator<Item = FSub>,
	b: impl IntoIterator<Item = F>,
) -> F
where
	F: Field + ExtensionField<FSub>,
	FSub: Field,
{
	itertools::zip_eq(a, b).map(|(a_i, b_i)| b_i * a_i).sum()
}

#[inline]
pub fn inner_product_par<F, P, DataA, DataB>(
	a: &FieldBuffer<P, DataA>,
	b: &FieldBuffer<P, DataB>,
) -> F
where
	F: Field,
	P: PackedField<Scalar = F>,
	DataA: Deref<Target = [P]>,
	DataB: Deref<Target = [P]>,
{
	a.as_ref()
		.par_iter()
		.zip_eq(b.as_ref().par_iter())
		.map(|(&a_i, &b_i)| a_i * b_i)
		.sum::<P>()
		.into_iter()
		.sum()
}

#[inline]
pub fn inner_product_packed<F, P, DataA, DataB>(
	a: &FieldBuffer<P, DataA>,
	b: &FieldBuffer<P, DataB>,
) -> F
where
	F: Field,
	P: PackedField<Scalar = F>,
	DataA: Deref<Target = [P]>,
	DataB: Deref<Target = [P]>,
{
	itertools::zip_eq(a.as_ref(), b.as_ref())
		.map(|(&a_i, &b_i)| a_i * b_i)
		.sum::<P>()
		.into_iter()
		.sum()
}
