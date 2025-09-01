use thiserror::Error;

/// Error types for the prover interface
#[derive(Debug, Error)]
pub enum ProverError {
    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] binius_utils::serialization::SerializationError),

    /// FFI error from the closed-source prover
    #[error("FFI error (code {0})")]
    FFIError(i32),

    /// Library not available
    #[error("Library not available: {0}")]
    LibraryNotAvailable(String),

    /// Prover operation failed
    #[error("Prover failed: {0}")]
    ProverFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl ProverError {
    /// Create an error from an FFI error code
    pub fn from_ffi_code(code: i32) -> Self {
        match code {
            -1 => ProverError::ProverFailed("General prover failure".to_string()),
            -2 => ProverError::InvalidInput("Invalid constraint system".to_string()),
            -3 => ProverError::InvalidInput("Invalid witness data".to_string()),
            -4 => ProverError::ProverFailed("Out of memory".to_string()),
            _ => ProverError::FFIError(code),
        }
    }
}

/// Result type for prover operations
pub type Result<T> = std::result::Result<T, ProverError>;