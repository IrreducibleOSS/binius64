mod error;
mod prove;

pub use error::Error;
pub use prove::prove;

#[cfg(test)]
pub mod tests;
