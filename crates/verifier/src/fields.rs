//! Exports the binary fields that this system uses

use binius_field::{BinaryField1b, BinaryField128b, BinaryField128bGhash, BinaryField128bPolyval};

pub type B1 = BinaryField1b;
pub type B128 = BinaryField128bGhash;
// pub type B128 = BinaryField128bPolyval;
// pub type B128 = BinaryField128b;
