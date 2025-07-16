use binius_field::{BinaryField1b, BinaryField16b, BinaryField128b};

pub const LOG_INV_RATE: usize = 1;
pub type SmallField = BinaryField1b;
pub const NUM_TEST_QUERIES: usize = 3;
pub const KAPPA: usize = 7; // variables to pack (128 = 2^7)
pub type BigField = BinaryField128b;
pub type FA = BinaryField16b;
