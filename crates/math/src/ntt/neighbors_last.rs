// Copyright 2024-2025 Irreducible Inc.

use std::{
	cmp::{max, min},
	slice::from_raw_parts_mut,
};

use binius_field::PackedField;
use binius_utils::rayon::{
	iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator},
	slice::ParallelSliceMut,
};

use super::{AdditiveNTT, DomainContext};

/// Runs a **part** of an NTT butterfly network, in depth-first order.
///
/// Concretely, it processes a specific block in the butterfly network, which is given by `layer`
/// and `block`, but continues to process future layers of this memory chunk, until `layer_bound`
/// (exclusive).
///
/// For example, suppose `layer=2` and `block=2`.
/// That means we are in an NTT butterfly network in layer 2 (the third layer) and block 2 (the
/// third block in this layer, there are four blocks in total in this layer). `data` contains the
/// data of this block, so it's only a chunk of the total data used in the NTT. Now suppose
/// `layer_bound=5`. Then we will process the following butterfly blocks:
/// - `layer=2` `block=2`
/// - `layer=3` `block=4`
/// - `layer=3` `block=5`
/// - `layer=4` `block=8`
/// - `layer=4` `block=9`
/// - `layer=4` `block=10`
/// - `layer=4` `block=11`
///
/// (Just in a different order. We listed breadth-first order, we would process them in
/// depth-first order).
fn forward_depth_first<P: PackedField>(
	domain_context: &impl DomainContext<Field = P::Scalar>,
	data: &mut [P],
	log_d: usize,
	layer: usize,
	block: usize,
	layer_bound: usize,
) {
	assert_eq!(data.len(), 1usize << (log_d - P::LOG_WIDTH));

	if layer >= layer_bound {
		return;
	}

	// if the problem size is small, we just do breadth_first (to get rid of the stack overhead)
	// we also need to do that if the number of scalars is just two times our packing width, i.e. if
	// we only have two packed elements in our data slice
	if log_d <= 4 || log_d <= P::LOG_WIDTH + 1 {
		forward_breadth_first(domain_context, data, log_d, layer, block, layer_bound);
		return;
	}

	// process only one layer of this block
	let block_size_half = 1 << (log_d - 1 - P::LOG_WIDTH);
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

	// then recurse
	forward_depth_first(
		domain_context,
		&mut data[..block_size_half],
		log_d - 1,
		layer + 1,
		block << 1,
		layer_bound,
	);
	forward_depth_first(
		domain_context,
		&mut data[block_size_half..],
		log_d - 1,
		layer + 1,
		(block << 1) + 1,
		layer_bound,
	);
}

/// Same as [`forward_depth_first`], but runs in breadth-first order.
fn forward_breadth_first<P: PackedField>(
	domain_context: &impl DomainContext<Field = P::Scalar>,
	data: &mut [P],
	log_d: usize,
	layer: usize,
	block: usize,
	layer_bound: usize,
) {
	assert_eq!(data.len(), 1 << (log_d - P::LOG_WIDTH));
	assert!(log_d >= 1);

	let num_packed_layers_left = log_d - P::LOG_WIDTH;
	let first_interleaved_layer = layer + num_packed_layers_left;
	let packed_layers = layer..min(first_interleaved_layer, layer_bound);
	let interleaved_layers = first_interleaved_layer..layer_bound;

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
/// (The latter is the purpose of this function. If the number of shares is small enough (and the
/// number of blocks is big enough) so that we don't need to split up blocks, we could just run
/// [`forward_depth_first`] on disjoint chunks.)
fn forward_shared_layer<P: PackedField>(
	domain_context: &(impl DomainContext<Field = P::Scalar> + Sync),
	data: &mut [P],
	log_d: usize,
	layer: usize,
	log_num_shares: usize,
) {
	let log_num_chunks = log_num_shares + 1;
	assert!(log_num_chunks <= log_d);
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

/// Returns `log_d`, the base-2 log of the total number of scalars in the input.
fn input_check<P: PackedField>(data: &[P], skip_early: usize, skip_late: usize) -> usize {
	// we only accept input of power-of-two length
	assert!(data.len().is_power_of_two());
	// d = number of scalars in the input
	let log_d = data.len().ilog2() as usize + P::LOG_WIDTH;

	// we can't "double-skip" layers
	assert!(skip_early + skip_late <= log_d);

	// to do interleaving, we need at least 2 input elements
	let needs_interleaving = skip_late < P::LOG_WIDTH;
	if needs_interleaving {
		assert!(data.len() >= 2);
	}

	log_d
}

/// A single-threaded implementation of [`AdditiveNTT`].
///
/// Note that "neighbors last" refers to the memory layout for the NTT: In the _last_ layer of this
/// NTT algorithm, neighboring elements speak to each other. In the classic FFT that's usually the
/// case for "decimation in frequency".
#[derive(Debug)]
pub struct NeighborsLastSingleThread<DC> {
	/// The domain context from which the twiddles are pulled.
	pub domain_context: DC,
}

impl<DC: DomainContext> AdditiveNTT<DC::Field> for NeighborsLastSingleThread<DC> {
	/// ## Preconditions
	///
	/// - `data` has power-of-2 length
	/// - `skip_early + skip_late` is at most the total number of layers needed (which is
	///   `data.len() + P::LOG_WIDTH`)
	/// - if interleaved layers are needed (which is the case when `skip_late < P::LOG_WIDTH`) then
	///   we need `data.len() >= 2`
	fn forward_transform<P: PackedField<Scalar = DC::Field>>(
		&self,
		data: &mut [P],
		skip_early: usize,
		skip_late: usize,
	) {
		// total number of scalars
		let log_d = input_check(data, skip_early, skip_late);
		// number of scalars per block in layer skip_early
		let log_d_chunk = log_d - skip_early;
		data.chunks_mut(1 << (log_d_chunk - P::LOG_WIDTH))
			.enumerate()
			.for_each(|(block, chunk)| {
				forward_depth_first(
					&self.domain_context,
					chunk,
					log_d_chunk,
					skip_early,
					block,
					log_d - skip_late,
				);
			});
	}

	fn domain_context(&self) -> &impl DomainContext<Field = DC::Field> {
		&self.domain_context
	}
}

/// A multi-threaded implementation of [`AdditiveNTT`].
///
/// Note that "neighbors last" refers to the memory layout for the NTT: In the _last_ layer of this
/// NTT algorithm, neighboring elements speak to each other. In the classic FFT that's usually the
/// case for "decimation in frequency".
#[derive(Debug)]
pub struct NeighborsLastMultiThread<DC> {
	/// The domain context from which the twiddles are pulled.
	pub domain_context: DC,
	/// The base-2 logarithm of number of equal-sized shares that the problem should be split into.
	/// Each share needs to do the same amount of work. If you have equally powered cores
	/// available, this should be the base-2 logarithm of the number of cores.
	pub log_num_shares: usize,
}

impl<DC: DomainContext + Sync> AdditiveNTT<DC::Field> for NeighborsLastMultiThread<DC> {
	/// ## Preconditions
	///
	/// - `data.len() <= self.log_num_shares`
	/// - everything from [`NeighborsLastSingleThread`]
	fn forward_transform<P: PackedField<Scalar = DC::Field>>(
		&self,
		data: &mut [P],
		skip_early: usize,
		skip_late: usize,
	) {
		// total number of scalars
		let log_d = input_check(data, skip_early, skip_late);

		let first_interleaved_layer = log_d - P::LOG_WIDTH;
		let first_independent_layer = self.log_num_shares;
		// multiple threads cannot work on the same packed element
		// NOTE: We could also artificially decrease the number of shares, but then the user would
		// experience an unexpectedly low performance without warning.
		assert!(first_independent_layer <= first_interleaved_layer);

		for layer in skip_early..first_independent_layer {
			forward_shared_layer(&self.domain_context, data, log_d, layer, self.log_num_shares);
		}

		let layer = max(first_independent_layer, skip_early);
		let log_d_chunk = log_d - layer;
		data.par_chunks_mut(1 << (log_d_chunk - P::LOG_WIDTH))
			.enumerate()
			.for_each(|(block, chunk)| {
				forward_depth_first(
					&self.domain_context,
					chunk,
					log_d_chunk,
					layer,
					block,
					log_d - skip_late,
				);
			});
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
