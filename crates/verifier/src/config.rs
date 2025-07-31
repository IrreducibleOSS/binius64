//! Specifies standard trait implementations and parameters.

use binius_field::BinaryField;
use binius_transcript::fiat_shamir::HasherChallenger;
use binius_utils::checked_arithmetics::checked_log_2;

use super::{fields::B128, hash::StdDigest};

/// The default [`binius_transcript::fiat_shamir::Challenger`] implementation.
pub type StdChallenger = HasherChallenger<StdDigest>;

/// The protocol proves constraint systems over 64-bit words.
pub const WORD_SIZE_BITS: usize = 64;

/// log2 of [`WORD_SIZE_BITS`].
pub const LOG_WORD_SIZE_BITS: usize = checked_log_2(WORD_SIZE_BITS);
pub const LOG_WORDS_PER_ELEM: usize = checked_log_2(B128::N_BITS) - LOG_WORD_SIZE_BITS;
