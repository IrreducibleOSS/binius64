// 4,5,6 supported but 6 is optimal
pub const SKIPPED_VARS: usize = 6;

// This is the amount of hypercubes in the "oblong hypercube"
pub const ROWS_PER_HYPERCUBE_VERTEX: usize = 1 << SKIPPED_VARS;
