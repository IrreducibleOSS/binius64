use binius_field::BinaryField;
use binius_math::{line::extrapolate_line_packed, ntt::DomainContext};

#[inline]
fn fold_pair<F: BinaryField>(
	values: (F, F),
	fold_challenge: F,
	domain_context: &impl DomainContext<Field = F>,
	log_len: usize,
	index: usize,
) -> F {
	// inverse additive NTT butterfly
	let twiddle = domain_context.twiddle(log_len - 1, index);
	let (mut u, mut v) = values;
	v += u;
	u += v * twiddle;
	// println!(
	// 	"fold_pair finished with u={u} v={v} fold_challenge={fold_challenge} and folded val {}",
	// 	extrapolate_line_packed(u, v, fold_challenge)
	// );
	// fold
	extrapolate_line_packed(u, v, fold_challenge)
}

#[inline]
pub fn fold_chunk<F: BinaryField>(
	chunk: &[F],
	fold_challenges: &[F],
	domain_context: &impl DomainContext<Field = F>,
	mut log_len: usize,
	chunk_index: usize,
	scratch_buffer: &mut [F],
) -> F {
	let log_chunk_len = fold_challenges.len();
	debug_assert_eq!(chunk.len(), 1 << log_chunk_len);
	let mut log_chunk_len_half = log_chunk_len - 1;

	let (&first, remainder) = fold_challenges.split_first().unwrap();

	// fold first challenge
	for index_pair in 0..1 << log_chunk_len_half {
		let index_left = index_pair << 1;
		let index_right = index_left | 1;
		let pair = (chunk[index_left], chunk[index_right]);
		let global_index = (chunk_index << log_chunk_len_half) | index_pair;
		scratch_buffer[index_pair] = fold_pair(pair, first, domain_context, log_len, global_index);
	}

	// fold the remaining challenges
	for &fold_challenge in remainder {
		log_chunk_len_half -= 1;
		log_len -= 1;
		for index_pair in 0..1 << log_chunk_len_half {
			let index_left = index_pair << 1;
			let index_right = index_left | 1;
			let pair = (scratch_buffer[index_left], scratch_buffer[index_right]);
			let global_index = (chunk_index << log_chunk_len_half) | index_pair;
			scratch_buffer[index_pair] =
				fold_pair(pair, fold_challenge, domain_context, log_len, global_index);
		}
	}

	scratch_buffer[0]
}

#[inline]
pub fn fold_chunk_in_place<F: BinaryField>(
	chunk: &mut [F],
	fold_challenges: &[F],
	domain_context: &impl DomainContext<Field = F>,
	mut log_len: usize,
	chunk_index: usize,
) -> F {
	let log_chunk_len = fold_challenges.len();
	debug_assert_eq!(chunk.len(), 1 << log_chunk_len);
	// note that we subtract 1 at the start of the loop below
	// (we can't put the subtraction at the end of the loop because of underflow in the last iteration)
	let mut log_chunk_len_half = log_chunk_len;
	log_len += 1;

	// fold first challenge
	for &fold_challenge in fold_challenges {
		log_chunk_len_half -= 1;
		log_len -= 1;
		for index_pair in 0..1 << log_chunk_len_half {
			let index_left = index_pair << 1;
			let index_right = index_left | 1;
			let pair = (chunk[index_left], chunk[index_right]);
			let global_index = (chunk_index << log_chunk_len_half) | index_pair;
			chunk[index_pair] =
				fold_pair(pair, fold_challenge, domain_context, log_len, global_index);
		}
	}

	chunk[0]
}

#[inline]
pub fn fold_chunk_without_ntt<F: BinaryField>(
	chunk: &[F],
	fold_challenges: &[F],
	scratch_buffer: &mut [F],
) -> F {
	let log_chunk_len = fold_challenges.len();
	debug_assert_eq!(chunk.len(), 1 << log_chunk_len);
	let mut log_chunk_len_half = log_chunk_len - 1;

	let (&first, remainder) = fold_challenges.split_first().unwrap();

	// fold first challenge
	for index_pair in 0..1 << log_chunk_len_half {
		let index_left = index_pair << 1;
		let index_right = index_left | 1;
		let (u, v) = (chunk[index_left], chunk[index_right]);
		scratch_buffer[index_pair] = extrapolate_line_packed(u, v, first)
	}

	// fold the remaining challenges
	for &fold_challenge in remainder {
		log_chunk_len_half -= 1;
		for index_pair in 0..1 << log_chunk_len_half {
			let index_left = index_pair << 1;
			let index_right = index_left | 1;
			let (u, v) = (scratch_buffer[index_left], scratch_buffer[index_right]);
			scratch_buffer[index_pair] = extrapolate_line_packed(u, v, fold_challenge)
		}
	}

	scratch_buffer[0]
}

#[inline]
pub fn fold_chunk_without_ntt_in_place<F: BinaryField>(
	chunk: &mut [F],
	fold_challenges: &[F],
) -> F {
	let log_chunk_len = fold_challenges.len();
	debug_assert_eq!(chunk.len(), 1 << log_chunk_len);
	// note that we subtract 1 at the start of the loop below
	// (we can't put the subtraction at the end of the loop because of underflow in the last iteration)
	let mut log_chunk_len_half = log_chunk_len;

	// fold the remaining challenges
	for &fold_challenge in fold_challenges {
		log_chunk_len_half -= 1;
		for index_pair in 0..1 << log_chunk_len_half {
			let index_left = index_pair << 1;
			let index_right = index_left | 1;
			let (u, v) = (chunk[index_left], chunk[index_right]);
			chunk[index_pair] = extrapolate_line_packed(u, v, fold_challenge)
		}
	}

	chunk[0]
}
