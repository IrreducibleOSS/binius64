//! Specifies standard trait implementations and parameters.

use binius_field::{AESTowerField8b, BinaryField, BinaryField1b, BinaryField128bGhash};
use binius_transcript::fiat_shamir::HasherChallenger;
use binius_utils::checked_arithmetics::checked_log_2;

use super::hash::StdDigest;

// Exports the binary fields that this system uses
pub type B1 = BinaryField1b;
pub type B128 = BinaryField128bGhash;

/// The default [`binius_transcript::fiat_shamir::Challenger`] implementation.
pub type StdChallenger = HasherChallenger<StdDigest>;

/// The protocol proves constraint systems over 64-bit words.
pub const WORD_SIZE_BITS: usize = 64;

/// log2 of [`WORD_SIZE_BITS`].
pub const LOG_WORD_SIZE_BITS: usize = checked_log_2(WORD_SIZE_BITS);
pub const LOG_WORDS_PER_ELEM: usize = checked_log_2(B128::N_BITS) - LOG_WORD_SIZE_BITS;

pub const PROVER_SMALL_FIELD_ZEROCHECK_CHALLENGES: [AESTowerField8b; 3] = [
	AESTowerField8b::new(0x2),
	AESTowerField8b::new(0x4),
	AESTowerField8b::new(0x10),
];
