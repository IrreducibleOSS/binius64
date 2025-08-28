// error.rs - Error types for the prover interface

use thiserror::Error;

/// Error types for the prover interface
#[derive(Debug, Error)]
pub enum ProverError {
    /// Invalid witness provided
    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    /// Prover operation failed
    #[error("Prover failed: {0}")]
    ProverFailed(String),

    /// Failed to initialize the prover
    #[error("Failed to initialize prover")]
    InitializationFailed,

    /// FFI error from the closed-source prover
    #[error("FFI error (code {0})")]
    FFIError(i32),
}

impl ProverError {
    /// Create an error from an FFI error code
    pub fn from_ffi_code(code: i32) -> Self {
        ProverError::FFIError(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ProverError::InvalidWitness("too short".to_string());
        assert_eq!(err.to_string(), "Invalid witness: too short");

        let err = ProverError::ProverFailed("internal error".to_string());
        assert_eq!(err.to_string(), "Prover failed: internal error");

        let err = ProverError::InitializationFailed;
        assert_eq!(err.to_string(), "Failed to initialize prover");
    }

    #[test]
    fn test_error_from_ffi_code() {
        let err = ProverError::from_ffi_code(-1);
        assert!(matches!(err, ProverError::FFIError(_)));

        let err = ProverError::from_ffi_code(-100);
        assert!(err.to_string().contains("FFI error"));
    }

    #[test]
    fn test_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ProverError::InvalidWitness("test".to_string()));
        assert_eq!(err.to_string(), "Invalid witness: test");
    }
}