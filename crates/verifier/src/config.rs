//! Specifies standard trait implementations and parameters.

use binius_transcript::fiat_shamir::HasherChallenger;

use crate::hash::StdDigest;

/// The default [`binius_transcript::fiat_shamir::Challenger`] implementation.
pub type StdChallenger = HasherChallenger<StdDigest>;
