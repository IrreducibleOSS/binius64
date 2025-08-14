pub mod compress;
mod serialization;
#[allow(dead_code)]
mod vision;

pub use compress::{CompressionFunction, PseudoCompressionFunction};
pub use serialization::*;

/// The standard digest is SHA-256.
pub type StdDigest = sha2::Sha256;
pub type StdCompression = compress::sha256::Sha256Compression;
