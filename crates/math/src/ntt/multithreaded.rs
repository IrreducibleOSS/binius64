// Copyright 2024-2025 Irreducible Inc.

use binius_field::{BinaryField, PackedField};
use binius_utils::{
	rayon::{config::get_log_max_threads, prelude::*},
	strided_array::StridedArray2DViewMut,
};

use super::{
	additive_ntt::{AdditiveNTT, NTTShape},
	error::Error,
	single_threaded::{SingleThreadedNTT, check_batch_transform_inputs_and_params},
	twiddle::{OnTheFlyTwiddleAccess, TwiddleAccess},
};
use crate::BinarySubspace;

/// Implementation of `AdditiveNTT` that performs the computation multithreaded.
#[derive(Debug)]
pub struct MultiThreadedNTT<F, TA = OnTheFlyTwiddleAccess<F, Vec<F>>> {
	single_threaded: SingleThreadedNTT<F, TA>,
	log_max_threads: usize,
}

impl<F: BinaryField, TA: TwiddleAccess<F> + Sync> SingleThreadedNTT<F, TA> {
	/// Returns multithreaded NTT implementation which uses default number of threads.
	pub fn multithreaded(self) -> MultiThreadedNTT<F, TA> {
		let log_max_threads = get_log_max_threads();
		self.multithreaded_with_max_threads(log_max_threads as _)
	}

	/// Returns multithreaded NTT implementation which uses `1 << log_max_threads` threads.
	pub const fn multithreaded_with_max_threads(
		self,
		log_max_threads: usize,
	) -> MultiThreadedNTT<F, TA> {
		MultiThreadedNTT {
			single_threaded: self,
			log_max_threads,
		}
	}
}

impl<F, TA> AdditiveNTT<F> for MultiThreadedNTT<F, TA>
where
	F: BinaryField,
	TA: TwiddleAccess<F> + Sync,
{
	fn log_domain_size(&self) -> usize {
		self.single_threaded.log_domain_size()
	}

	fn subspace(&self, i: usize) -> BinarySubspace<F> {
		self.single_threaded.subspace(i)
	}

	fn get_subspace_eval(&self, i: usize, j: usize) -> F {
		self.single_threaded.get_subspace_eval(i, j)
	}

	fn forward_transform<P: PackedField<Scalar = F>>(
		&self,
		data: &mut [P],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error> {
		forward_transform(
			&self.single_threaded,
			data,
			shape,
			coset,
			coset_bits,
			skip_rounds,
			self.log_max_threads,
		)
	}

	fn inverse_transform<P: PackedField<Scalar = F>>(
		&self,
		data: &mut [P],
		shape: NTTShape,
		coset: usize,
		coset_bits: usize,
		skip_rounds: usize,
	) -> Result<(), Error> {
		inverse_transform(
			&self.single_threaded,
			data,
			shape,
			coset,
			coset_bits,
			skip_rounds,
			self.log_max_threads,
		)
	}
}

#[allow(clippy::too_many_arguments)]
fn forward_transform<F, P, TA>(
	subntt: &SingleThreadedNTT<F, TA>,
	data: &mut [P],
	shape: NTTShape,
	coset: usize,
	coset_bits: usize,
	skip_rounds: usize,
	log_max_threads: usize,
) -> Result<(), Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	TA: TwiddleAccess<F> + Sync,
{
	check_batch_transform_inputs_and_params(
		subntt.log_domain_size(),
		data,
		shape,
		coset,
		coset_bits,
		skip_rounds,
	)?;

	match data.len() {
		0 => return Ok(()),
		1 => {
			return match P::WIDTH {
				1 => Ok(()),
				_ => subntt.forward_transform(data, shape, coset, coset_bits, skip_rounds),
			};
		}
		_ => {}
	};

	let NTTShape {
		log_x,
		log_y,
		log_z,
	} = shape;

	let log_w = P::LOG_WIDTH;

	// Determine the optimal log_height and log_width, measured in packed field elements. log_width
	// must be at least 1, so that the row-wise NTTs have pairs of butterfly blocks to work with.
	// Furthermore, we want the number of scalars in the width to be at least log_x, so that each
	// row-wise NTT operates on full batches. Subject to the minimum width requirement, we want to
	// set the height to the lowest value that takes advantage of all available threads.
	let min_log_width_scalars = (log_w + 1).max(log_x);

	// The subtraction must not underflow because data is checked to have at least 2 packed
	// elements at the top of the function.
	let log_height = (log_x + log_y + log_z - min_log_width_scalars).min(log_max_threads);
	let log_width = log_x + log_y + log_z - (log_w + log_height);

	// The NTT algorithm shapes the tensor into a 2D matrix and runs two phases:
	//
	// 1. The first phase performs strided column-wise NTTs.
	// 2. The second phase performs the row-wise NTTs.

	// par_rounds is the number of phase 1 strided rounds.
	let par_rounds = log_height.saturating_sub(log_z);

	// Perform the column-wise NTTs in parallel over vertical strides of the matrix.
	{
		let matrix = StridedArray2DViewMut::without_stride(data, 1 << log_height, 1 << log_width)
			.expect("dimensions are correct");

		let log_strides = log_max_threads.min(log_width);
		let log_stride_len = log_width - log_strides;

		let log_domain_size = subntt.log_domain_size();
		let s_evals = &subntt.twiddles()[log_domain_size - (par_rounds + coset_bits)..];

		matrix
			.into_par_strides(1 << log_stride_len)
			.for_each(|mut stride| {
				// i indexes the layer of the NTT network, also the binary subspace.
				for i in (0..par_rounds.saturating_sub(skip_rounds)).rev() {
					let s_evals_par_i = &s_evals[i];
					let coset_offset = coset << (par_rounds - 1 - i);

					// j indexes the outer Z tensor axis.
					for j in 0..1 << log_z {
						// k indexes the block within the layer. Each block performs butterfly
						// operations with the same twiddle factor.
						for k in 0..1 << (par_rounds - 1 - i) {
							let twiddle = P::broadcast(s_evals_par_i.get(coset_offset | k));
							// l indexes parallel stride columns
							for l in 0..1 << i {
								for m in 0..1 << log_stride_len {
									let idx0 = j << par_rounds | k << (i + 1) | l;
									let idx1 = idx0 | 1 << i;

									let mut u = stride[(idx0, m)];
									let mut v = stride[(idx1, m)];
									u += v * twiddle;
									v += u;
									stride[(idx0, m)] = u;
									stride[(idx1, m)] = v;
								}
							}
						}
					}
				}
			});
	}

	let log_row_z = log_z.saturating_sub(log_height);
	let single_thread_log_y = log_width + log_w - log_x - log_row_z;

	data.par_chunks_mut(1 << (log_width + par_rounds))
		.flat_map(|large_chunk| large_chunk.par_chunks_mut(1 << log_width).enumerate())
		.try_for_each(|(inner_coset, chunk)| {
			subntt.forward_transform(
				chunk,
				NTTShape {
					log_x,
					log_y: single_thread_log_y,
					log_z: log_row_z,
				},
				coset << par_rounds | inner_coset,
				coset_bits + par_rounds,
				skip_rounds.saturating_sub(par_rounds),
			)
		})?;

	Ok(())
}

#[allow(clippy::too_many_arguments)]
fn inverse_transform<F, P, TA>(
	subntt: &SingleThreadedNTT<F, TA>,
	data: &mut [P],
	shape: NTTShape,
	coset: usize,
	coset_bits: usize,
	skip_rounds: usize,
	log_max_threads: usize,
) -> Result<(), Error>
where
	F: BinaryField,
	P: PackedField<Scalar = F>,
	TA: TwiddleAccess<F> + Sync,
{
	check_batch_transform_inputs_and_params(
		subntt.log_domain_size(),
		data,
		shape,
		coset,
		coset_bits,
		skip_rounds,
	)?;

	match data.len() {
		0 => return Ok(()),
		1 => {
			return match P::WIDTH {
				1 => Ok(()),
				_ => subntt.inverse_transform(data, shape, coset, coset_bits, skip_rounds),
			};
		}
		_ => {}
	};

	let NTTShape {
		log_x,
		log_y,
		log_z,
	} = shape;

	let log_w = P::LOG_WIDTH;

	// Determine the optimal log_height and log_width, measured in packed field elements. log_width
	// must be at least 1, so that the row-wise NTTs have pairs of butterfly blocks to work with.
	// Furthermore, we want the number of scalars in the width to be at least log_x, so that each
	// row-wise NTT operates on full batches. Subject to the minimum width requirement, we want to
	// set the height to the lowest value that takes advantage of all available threads.
	let min_log_width_scalars = (log_w + 1).max(log_x);

	// The subtraction must not underflow because data is checked to have at least 2 packed
	// elements at the top of the function.
	let log_height = (log_x + log_y + log_z - min_log_width_scalars).min(log_max_threads);
	let log_width = log_x + log_y + log_z - (log_w + log_height);

	// The iNTT algorithm shapes the tensor into a 2D matrix and runs two phases:
	//
	// 1. The first phase performs the row-wise iNTTs.
	// 2. The second phase performs strided column-wise iNTTs.

	// par_rounds is the number of phase 2 strided rounds.
	let par_rounds = log_height.saturating_sub(log_z);

	let log_row_z = log_z.saturating_sub(log_height);
	let single_thread_log_y = log_width + log_w - log_x - log_row_z;

	data.par_chunks_mut(1 << (log_width + par_rounds))
		.flat_map(|large_chunk| large_chunk.par_chunks_mut(1 << log_width).enumerate())
		.try_for_each(|(inner_coset, chunk)| {
			subntt.inverse_transform(
				chunk,
				NTTShape {
					log_x,
					log_y: single_thread_log_y,
					log_z: log_row_z,
				},
				coset << par_rounds | inner_coset,
				coset_bits + par_rounds,
				skip_rounds.saturating_sub(par_rounds),
			)
		})?;

	// Perform the column-wise NTTs in parallel over vertical strides of the matrix.
	let matrix = StridedArray2DViewMut::without_stride(data, 1 << log_height, 1 << log_width)
		.expect("dimensions are correct");

	let log_strides = log_max_threads.min(log_width);
	let log_stride_len = log_width - log_strides;

	let log_domain_size = subntt.log_domain_size();
	let s_evals = &subntt.twiddles()[log_domain_size - (par_rounds + coset_bits)..];

	matrix
		.into_par_strides(1 << log_stride_len)
		.for_each(|mut stride| {
			// i indexes the layer of the NTT network, also the binary subspace.
			#[allow(clippy::needless_range_loop)]
			for i in 0..par_rounds.saturating_sub(skip_rounds) {
				let s_evals_par_i = &s_evals[i];
				let coset_offset = coset << (par_rounds - 1 - i);

				// j indexes the outer Z tensor axis.
				for j in 0..1 << log_z {
					// k indexes the block within the layer. Each block performs butterfly
					// operations with the same twiddle factor.
					for k in 0..1 << (par_rounds - 1 - i) {
						let twiddle = P::broadcast(s_evals_par_i.get(coset_offset | k));
						// l indexes parallel stride columns
						for l in 0..1 << i {
							for m in 0..1 << log_stride_len {
								let idx0 = j << par_rounds | k << (i + 1) | l;
								let idx1 = idx0 | 1 << i;

								let mut u = stride[(idx0, m)];
								let mut v = stride[(idx1, m)];
								v += u;
								u += v * twiddle;
								stride[(idx0, m)] = u;
								stride[(idx1, m)] = v;
							}
						}
					}
				}
			}
		});

	Ok(())
}
