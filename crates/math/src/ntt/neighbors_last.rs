// Copyright 2024-2025 Irreducible Inc.

use std::{
	cmp::{max, min},
	ops::Range,
	slice::from_raw_parts_mut,
};

use binius_field::PackedField;
use binius_utils::rayon::{
	iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
	slice::ParallelSliceMut,
};

use super::{AdditiveNTT, DomainContext};
use crate::{FieldSlice, FieldSliceMut};

const DEFAULT_LOG_BASE_LEN: usize = 4;

/// Reference implementation of [`AdditiveNTT`].
///
/// This is slow. Do not use in production.
pub struct NeighborsLastReference<DC> {
	pub domain_context: DC,
}

impl<DC: DomainContext> AdditiveNTT for NeighborsLastReference<DC> {
	type Field = DC::Field;

	fn forward_transform<P: PackedField<Scalar = Self::Field>>(
		&self,
		mut data: FieldSliceMut<P>,
		skip_early: usize,
		skip_late: usize,
	) {
		let log_d = data.log_len();

		for layer in skip_early..(log_d - skip_late) {
			let num_blocks = 1 << layer;
			let block_size_half = 1 << (log_d - layer - 1);
			for block in 0..num_blocks {
				let twiddle = self.domain_context.twiddle(layer, block);
				let block_start = block << (log_d - layer);
				for idx0 in block_start..(block_start + block_size_half) {
					let idx1 = block_size_half | idx0;
					// perform butterfly
					let mut u = data.get(idx0).unwrap();
					let mut v = data.get(idx1).unwrap();
					u += v * twiddle;
					v += u;
					data.set(idx0, u).unwrap();
					data.set(idx1, v).unwrap();
				}
			}
		}
	}

	fn inverse_transform<P: PackedField<Scalar = Self::Field>>(
		&self,
		mut data: FieldSliceMut<P>,
		skip_early: usize,
		skip_late: usize,
	) {
		let log_d = data.log_len();

		for layer in (skip_early..(log_d - skip_late)).rev() {
			let num_blocks = 1 << layer;
			let block_size_half = 1 << (log_d - layer - 1);
			for block in 0..num_blocks {
				let twiddle = self.domain_context.twiddle(layer, block);
				let block_start = block << (log_d - layer);
				for idx0 in block_start..(block_start + block_size_half) {
					let idx1 = block_size_half | idx0;
					// perform butterfly
					let mut u = data.get(idx0).unwrap();
					let mut v = data.get(idx1).unwrap();
					v += u;
					u += v * twiddle;
					data.set(idx0, u).unwrap();
					data.set(idx1, v).unwrap();
				}
			}
		}
	}

	fn domain_context(&self) -> &impl DomainContext<Field = DC::Field> {
		&self.domain_context
	}
}

/// Runs a **part** of an NTT butterfly network, in depth-first order.
///
/// Concretely, it processes a specific memory block in the butterfly network, which is given by
/// `layer` and `block`. For this memory block, it processes the layers given by `layer_range`.
///
/// For example, suppose `layer=2` and `block=2`.
/// That means we are in an NTT butterfly network in layer 2 (the third layer) and block 2 (the
/// third block in this layer, there are four blocks in total in this layer). `data` contains the
/// data of this block, so it's only a chunk of the total data used in the NTT. Now suppose
/// `layer_range=2..5`. Then we will process the following butterfly blocks:
/// - `layer=2` `block=2`
/// - `layer=3` `block=4`
/// - `layer=3` `block=5`
/// - `layer=4` `block=8`
/// - `layer=4` `block=9`
/// - `layer=4` `block=10`
/// - `layer=4` `block=11`
///
/// (Just in a different order. We listed breadth-first order, we would process them in
/// depth-first order.)
///
/// The argument `log_base_len` determines for which `log_d` we call the breadth-first
/// implementation as a base case.
///
/// ## Preconditions
///
/// - `2^(log_d) == data.len() * packing_width`
/// - `data.len() >= 2`
/// - `domain_context` holds all the twiddles up to `layer_range.end` (exclusive)
/// - `layer <= layer_range.start`
fn forward_depth_first<P: PackedField>(
	domain_context: &impl DomainContext<Field = P::Scalar>,
	data: &mut [P],
	log_d: usize,
	layer: usize,
	block: usize,
	mut layer_range: Range<usize>,
	log_base_len: usize,
) {
	// check preconditions
	debug_assert_eq!(data.len() * (1 << P::LOG_WIDTH), 1 << log_d);
	debug_assert!(data.len() >= 2);
	debug_assert!(layer_range.end <= domain_context.log_domain_size());
	debug_assert!(layer <= layer_range.start);

	if layer >= layer_range.end {
		return;
	}

	// if the problem size is small, we just do breadth_first (to get rid of the stack overhead)
	// we also need to do that if the number of scalars is just two times our packing width, i.e. if
	// we only have two packed elements in our data slice
	if log_d <= log_base_len || data.len() <= 2 {
		forward_breadth_first(domain_context, data, log_d, layer, block, layer_range);
		return;
	}

	let block_size_half = 1 << (log_d - 1 - P::LOG_WIDTH);
	if layer >= layer_range.start {
		// process only one layer of this block
		let twiddle = domain_context.twiddle(layer, block);
		let twiddle = P::broadcast(twiddle);
		for idx0 in 0..block_size_half {
			let idx1 = block_size_half | idx0;
			// perform butterfly
			let mut u = data[idx0];
			let mut v = data[idx1];
			u += v * twiddle;
			v += u;
			data[idx0] = u;
			data[idx1] = v;
		}

		layer_range.start += 1;
	}

	// then recurse
	forward_depth_first(
		domain_context,
		&mut data[..block_size_half],
		log_d - 1,
		layer + 1,
		block << 1,
		layer_range.clone(),
		log_base_len,
	);
	forward_depth_first(
		domain_context,
		&mut data[block_size_half..],
		log_d - 1,
		layer + 1,
		(block << 1) + 1,
		layer_range,
		log_base_len,
	);
}

/// Same as [`forward_depth_first`], but runs in breadth-first order.
///
/// ## Preconditions
///
/// - `2^(log_d) == data.len() * packing_width`
/// - `data.len() >= 2`
/// - `domain_context` holds all the twiddles up to `layer_bound` (exclusive)
/// - `layer <= layer_range.start`
fn forward_breadth_first<P: PackedField>(
	domain_context: &impl DomainContext<Field = P::Scalar>,
	data: &mut [P],
	log_d: usize,
	layer: usize,
	block: usize,
	layer_range: Range<usize>,
) {
	// check preconditions
	debug_assert_eq!(data.len() * (1 << P::LOG_WIDTH), 1 << log_d);
	debug_assert!(data.len() >= 2);
	debug_assert!(layer_range.end <= domain_context.log_domain_size());
	debug_assert!(layer <= layer_range.start);

	let num_packed_layers_left = log_d - P::LOG_WIDTH;
	let first_interleaved_layer = layer + num_packed_layers_left;
	let first_interleaved_layer = max(first_interleaved_layer, layer_range.start);
	let packed_layers = layer_range.start..min(first_interleaved_layer, layer_range.end);
	let interleaved_layers = first_interleaved_layer..layer_range.end;

	// Run the layers where packing_width >= block_size_half.
	// In these layers, we can always process whole packed elements, we don't need to interleave
	// them or read/write "within" packed elements.
	for l in packed_layers {
		// there are 2^l total blocks in layer l, but we only want to process those which are
		// contained in `block`
		let l_rel = l - layer;
		let block_offset = block << l_rel;
		// there are 2^(log_d - l) total scalars in a block in layer l, but they come in
		// pairs, so we iterate over 2^(log_d - l - 1) many scalars
		let block_size_half = 1 << (log_d - l_rel - 1 - P::LOG_WIDTH);
		for b in 0..1 << l_rel {
			// all butterflys within a block share the same twiddle
			let twiddle = domain_context.twiddle(l, block_offset | b);
			let twiddle = P::broadcast(twiddle);
			let block_start = b << (log_d - l_rel - P::LOG_WIDTH);
			for idx0 in block_start..(block_start + block_size_half) {
				let idx1 = block_size_half | idx0;
				// perform butterfly
				let mut u = data[idx0];
				let mut v = data[idx1];
				u += v * twiddle;
				v += u;
				data[idx0] = u;
				data[idx1] = v;
			}
		}
	}

	// Run the layers where packing_width < block_size_half.
	// That is, we would need to work "within" packed field elements.
	// We solve this problem by interleaving the packed elements with each other.
	for l in interleaved_layers {
		let l_rel = l - layer;
		let block_offset = block << l_rel;
		let block_size_half = 1 << (log_d - l_rel - 1);
		let log_block_size_half = log_d - l_rel - 1;

		// calculate packed_twiddle_offset
		let mut packed_twiddle_offset = P::zero();
		let log_blocks_per_packed = P::LOG_WIDTH - log_block_size_half;
		for i in 0..1 << log_blocks_per_packed {
			let block_start = i << log_block_size_half;
			let twiddle_offset_i_index = rotate_right(i, log_blocks_per_packed);
			let twiddle_offset_i = domain_context.twiddle(l, twiddle_offset_i_index);
			for j in block_start..(block_start + block_size_half) {
				packed_twiddle_offset.set(j, twiddle_offset_i);
			}
		}

		for b in (0..data.len()).step_by(2) {
			let first_twiddle =
				domain_context.twiddle(l, block_offset | (b << (log_blocks_per_packed - 1)));
			let twiddle = P::broadcast(first_twiddle) + packed_twiddle_offset;
			let (mut u, mut v) = data[b].interleave(data[b | 1], log_block_size_half);
			u += v * twiddle;
			v += u;
			(data[b], data[b | 1]) = u.interleave(v, log_block_size_half);
		}
	}
}

/// Process a layer of the NTT butterfly network in parallel by splitting the work up into
/// `2^log_num_shares` many shares. This will also split up single *blocks* into multiple shares.
///
/// (The latter is the whole purpose of this function. If the number of shares is small enough (and
/// the number of blocks is big enough) so that we don't need to split up blocks, we could just run
/// [`forward_depth_first`] on disjoint chunks.)
///
/// - `2^(log_d) == data.len() * packing_width`
/// - **Important:** `2^log_num_shares * 2 <= data.len()` (every share is working with whole packed
///   elements, so every share needs at least 2 packed elements)
/// - `domain_context` holds the twiddles of `layer`
fn forward_shared_layer<P: PackedField>(
	domain_context: &(impl DomainContext<Field = P::Scalar> + Sync),
	data: &mut [P],
	log_d: usize,
	layer: usize,
	log_num_shares: usize,
) {
	// check preconditions
	debug_assert_eq!(data.len() * (1 << P::LOG_WIDTH), 1 << log_d);
	debug_assert!(1 << (log_num_shares + 1) <= data.len());
	debug_assert!(layer < domain_context.log_domain_size());

	let log_num_chunks = log_num_shares + 1;
	let log_d_chunk = log_d - log_num_chunks;
	let data_ptr = data.as_mut_ptr();
	let shift = log_num_shares - layer;
	let tasks: Vec<_> = (0..1 << log_num_shares)
		.map(|k| {
			let (chunk0, chunk1) = with_middle_bit(k, shift);
			let block = chunk0 >> (log_num_chunks - layer);
			assert!(P::LOG_WIDTH <= log_d_chunk);
			let log_chunk_len = log_d_chunk - P::LOG_WIDTH;
			let chunk0 = unsafe {
				from_raw_parts_mut(data_ptr.add(chunk0 << log_chunk_len), 1 << log_chunk_len)
			};
			let chunk1 = unsafe {
				from_raw_parts_mut(data_ptr.add(chunk1 << log_chunk_len), 1 << log_chunk_len)
			};
			let twiddle = domain_context.twiddle(layer, block);
			let twiddle = P::broadcast(twiddle);
			(chunk0, chunk1, twiddle)
		})
		.collect();

	tasks.into_par_iter().for_each(|(chunk0, chunk1, twiddle)| {
		for i in 0..chunk0.len() {
			let mut u = chunk0[i];
			let mut v = chunk1[i];
			u += v * twiddle;
			v += u;
			chunk0[i] = u;
			chunk1[i] = v;
		}
	});
}

/// Interprets `value` as a bit-sequence of `bits` many bits, and rotates them to the right.
/// For example: `rotate_right(0b0001011, 7) -> 0b1000101`
#[inline]
fn rotate_right(value: usize, bits: usize) -> usize {
	(value >> 1) | ((value & 1) << (bits - 1))
}

/// Inserts a bit into `k`. Returns both the version with `0` inserted and `1` inserted.
///
/// The first `shift` bits are preserved, then `0` or `1` is inserted, and then the remaining bits
/// of `k` follow.
///
/// ## Preconditions
///
/// - `shift` must be strictly greater than 0
fn with_middle_bit(k: usize, shift: usize) -> (usize, usize) {
	assert!(shift >= 1);

	// most significant and least significant bits, overlapping in one bit
	let ms = k >> (shift - 1);
	let ls = k & ((1 << shift) - 1);

	let k0 = ls | ((ms & !1) << shift);
	let k1 = ls | ((ms | 1) << shift);

	(k0, k1)
}

/// Checks for the preconditions of the `AdditiveNTT` transforms and returns `log_d`, the base-2 log
/// of the total number of scalars in the input.
fn input_check<P: PackedField>(
	domain_context: &impl DomainContext<Field = P::Scalar>,
	data: FieldSlice<P>,
	skip_early: usize,
	skip_late: usize,
) -> usize {
	let log_d = data.log_len();

	// we can't "double-skip" layers
	assert!(skip_early + skip_late <= log_d);

	// we need enough twiddles in `domain_context`
	assert!(log_d <= domain_context.log_domain_size() + skip_late);

	log_d
}

/// A single-threaded implementation of [`AdditiveNTT`].
///
/// The code only makes sure that it's fast for a _large_ data input.
/// For small inputs, it can be comparatively slow!
///
/// The implementation is depth-first, but calls a breadth-first implementation as a base case.
///
/// Note that "neighbors last" refers to the memory layout for the NTT: In the _last_ layer of this
/// NTT algorithm, neighboring elements speak to each other. In the classic FFT that's usually the
/// case for "decimation in frequency".
#[derive(Debug)]
pub struct NeighborsLastSingleThread<DC> {
	/// The domain context from which the twiddles are pulled.
	pub domain_context: DC,
	/// Determines when to switch from depth-first to the breadth-first base case.
	pub log_base_len: usize,
}

impl<DC> NeighborsLastSingleThread<DC> {
	/// Convenience constructor which sets `log_base_len` to a reasonable default.
	pub fn new(domain_context: DC) -> Self {
		Self {
			domain_context,
			log_base_len: DEFAULT_LOG_BASE_LEN,
		}
	}
}

impl<DC: DomainContext> AdditiveNTT for NeighborsLastSingleThread<DC> {
	type Field = DC::Field;

	fn forward_transform<P: PackedField<Scalar = Self::Field>>(
		&self,
		mut data_orig: FieldSliceMut<P>,
		skip_early: usize,
		skip_late: usize,
	) {
		// total number of scalars
		let log_d = input_check(&self.domain_context, data_orig.to_ref(), skip_early, skip_late);

		let data = data_orig.as_mut();

		// if there is only a single packed element, we don't want to bother with potential
		// interleaving issues in the future so we just call the (slow) reference NTT
		if data.len() == 1 {
			let reference_ntt = NeighborsLastReference {
				domain_context: &self.domain_context,
			};
			reference_ntt.forward_transform(data_orig, skip_early, skip_late);
			return;
		}

		forward_depth_first(
			&self.domain_context,
			data,
			log_d,
			0,
			0,
			skip_early..(log_d - skip_late),
			self.log_base_len,
		);
	}

	fn inverse_transform<P: PackedField<Scalar = Self::Field>>(
		&self,
		mut _data_orig: FieldSliceMut<P>,
		_skip_early: usize,
		_skip_late: usize,
	) {
		unimplemented!()
	}

	fn domain_context(&self) -> &impl DomainContext<Field = DC::Field> {
		&self.domain_context
	}
}

/// A multi-threaded implementation of [`AdditiveNTT`].
///
/// The code only makes sure that it's fast for a _large_ data input.
/// For small inputs, it can be comparatively slow!
///
/// The implementation is depth-first, but calls a breadth-first implementation as a base case.
///
/// Note that "neighbors last" refers to the memory layout for the NTT: In the _last_ layer of this
/// NTT algorithm, neighboring elements speak to each other. In the classic FFT that's usually the
/// case for "decimation in frequency".
#[derive(Debug)]
pub struct NeighborsLastMultiThread<DC> {
	/// The domain context from which the twiddles are pulled.
	pub domain_context: DC,
	/// Determines when to switch from depth-first to the breadth-first base case.
	pub log_base_len: usize,
	/// The base-2 logarithm of number of equal-sized shares that the problem should be split into.
	/// Each share needs to do the same amount of work. If you have equally powered cores
	/// available, this should be the base-2 logarithm of the number of cores.
	pub log_num_shares: usize,
}

impl<DC> NeighborsLastMultiThread<DC> {
	/// Convenience constructor which sets `log_base_len` to a reasonable default.
	pub fn new(domain_context: DC, log_num_shares: usize) -> Self {
		Self {
			domain_context,
			log_base_len: DEFAULT_LOG_BASE_LEN,
			log_num_shares,
		}
	}
}

impl<DC: DomainContext + Sync> AdditiveNTT for NeighborsLastMultiThread<DC> {
	type Field = DC::Field;

	fn forward_transform<P: PackedField<Scalar = Self::Field>>(
		&self,
		mut data_orig: FieldSliceMut<P>,
		skip_early: usize,
		skip_late: usize,
	) {
		// total number of scalars
		let log_d = input_check(&self.domain_context, data_orig.to_ref(), skip_early, skip_late);

		let data = data_orig.as_mut();

		// if there is only a single packed element, we don't want to bother with potential
		// interleaving issues in the future so we just call the (slow) reference NTT
		if data.len() == 1 {
			let reference_ntt = NeighborsLastReference {
				domain_context: &self.domain_context,
			};
			reference_ntt.forward_transform(data_orig, skip_early, skip_late);
			return;
		}

		// Decide on `actual_log_num_shares`, which also determines how many shared rounds we do.
		// By default this would just be `self.log_num_shares`, but we will potentially decrease it
		// in order to make sure that `2^log_num_shares * 2 <= data.len()`. This serves two
		// purposes:
		// - when we do the shared rounds, each thread should have at least 2 packed elements to
		//   work with, see the precondition of [`forward_shared_layer`]
		// - when we do the independent rounds, again each share should have `chunk.len() >= 2`
		//   because this is required by [`forward_depth_first`]
		let maximum_log_num_shares = log_d - P::LOG_WIDTH - 1;
		let actual_log_num_shares = min(self.log_num_shares, maximum_log_num_shares);
		let first_independent_layer = actual_log_num_shares;

		let last_layer = log_d - skip_late;
		let shared_layers = skip_early..min(first_independent_layer, last_layer);
		let independent_layers = max(first_independent_layer, skip_early)..last_layer;

		for layer in shared_layers {
			forward_shared_layer(&self.domain_context, data, log_d, layer, actual_log_num_shares);
		}

		// One might think that we could just call `forward_depth_first` with
		// `layer=independent_layers.start`. However, this would mean that the chunk size (that we
		// split into using `par_chunks_mut`) could be just one packed element, or even less than
		// one packed element.
		let layer = min(independent_layers.start, maximum_log_num_shares);
		let log_d_chunk = log_d - layer;
		data.par_chunks_exact_mut(1 << (log_d_chunk - P::LOG_WIDTH))
			.enumerate()
			.for_each(|(block, chunk)| {
				forward_depth_first(
					&self.domain_context,
					chunk,
					log_d_chunk,
					layer,
					block,
					independent_layers.clone(),
					self.log_base_len,
				);
			});
	}

	fn inverse_transform<P: PackedField<Scalar = Self::Field>>(
		&self,
		mut _data_orig: FieldSliceMut<P>,
		_skip_early: usize,
		_skip_late: usize,
	) {
		unimplemented!()
	}

	fn domain_context(&self) -> &impl DomainContext<Field = DC::Field> {
		&self.domain_context
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_rotate_right() {
		assert_eq!(rotate_right(0b1001011, 7), 0b1100101);
		assert_eq!(rotate_right(0b0001011, 7), 0b1000101);
		assert_eq!(rotate_right(0b0001010, 7), 0b0000101);
		assert_eq!(rotate_right(0b1, 1), 0b1);
		assert_eq!(rotate_right(0b0, 1), 0b0);
	}

	#[test]
	fn test_with_middle_bit() {
		assert_eq!(with_middle_bit(0b000, 1), (0b0000, 0b0010));
		assert_eq!(with_middle_bit(0b000, 2), (0b0000, 0b0100));
		assert_eq!(with_middle_bit(0b000, 3), (0b0000, 0b1000));

		assert_eq!(with_middle_bit(0b111, 1), (0b1101, 0b1111));
		assert_eq!(with_middle_bit(0b111, 2), (0b1011, 0b1111));
		assert_eq!(with_middle_bit(0b111, 3), (0b0111, 0b1111));

		assert_eq!(with_middle_bit(0b1110110, 2), (0b11101010, 0b11101110));
	}
}
