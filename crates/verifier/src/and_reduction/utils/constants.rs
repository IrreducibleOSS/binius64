use crate::{LOG_WORD_SIZE_BITS, WORD_SIZE_BITS};

/// log2 size of the univariate domain
pub const SKIPPED_VARS: usize = LOG_WORD_SIZE_BITS;

// Size of the univariate domain
pub const ROWS_PER_HYPERCUBE_VERTEX: usize = WORD_SIZE_BITS;
