// Copyright 2025 Irreducible Inc.
// The code is initially based on `maybe-rayon` crate, https://github.com/shssoichiro/maybe-rayon

use super::IntoParallelIterator;
use crate::iter::parallel_iterator::ParallelIterator;

pub trait FromParallelIterator<T> {
	fn from_par_iter<I>(par_iter: I) -> Self
	where
		I: IntoParallelIterator<Item = T>;
}

impl<T> FromParallelIterator<T> for Vec<T>
where
	T: Send,
{
	#[inline(always)]
	fn from_par_iter<I>(par_iter: I) -> Self
	where
		I: IntoParallelIterator<Item = T>,
	{
		par_iter.into_par_iter().into_inner().collect()
	}
}

impl<T, E> FromParallelIterator<Result<T, E>> for Result<Vec<T>, E>
where
	T: Send,
{
	#[inline(always)]
	fn from_par_iter<I>(par_iter: I) -> Self
	where
		I: IntoParallelIterator<Item = Result<T, E>>,
	{
		par_iter.into_par_iter().into_inner().collect()
	}
}
