use binius_field::{BinaryField1b, BinaryField16b, BinaryField128b};

pub const LOG_INV_RATE: usize = 1;
pub type SmallField = BinaryField1b;
pub const NUM_TEST_QUERIES: usize = 3;
pub const L: usize = 11; // variables in small field multilinear
pub const KAPPA: usize = 7; // variables to pack (128 = 2^7)
pub const L_PRIME: usize = L - KAPPA; // variables in packed multilinear
pub type BigField = BinaryField128b;
pub type FA = BinaryField16b;
