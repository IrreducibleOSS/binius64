// ffi.rs - Simplified FFI bindings using serialization

use crate::error::ProverError;

/// Simplified FFI interface using serialized data
/// 
/// The closed-source prover accepts serialized constraint system and witness data,
/// and returns a serialized proof. This greatly simplifies the FFI boundary.
pub fn prove_serialized(
    cs_bytes: &[u8],
    pub_witness_bytes: &[u8],
    priv_witness_bytes: &[u8],
    log_inv_rate: u32,
) -> Result<Vec<u8>, ProverError> {
    #[cfg(has_binius_prover)]
    {
        
        unsafe { ffi::prove_serialized(cs_bytes, pub_witness_bytes, priv_witness_bytes, log_inv_rate) }
    }
    
    #[cfg(not(has_binius_prover))]
    {
        // Suppress unused variable warnings when library is not available
        let _ = (cs_bytes, pub_witness_bytes, priv_witness_bytes, log_inv_rate);
        
        
        // When library is not available, return an error
        // This allows the code to compile but will fail at runtime
        Err(ProverError::LibraryNotAvailable(
            "Binius prover library not found. Set BINIUS_PROVER_LIB_PATH and rebuild.".to_string()
        ))
    }
}

// Real FFI declarations to the closed-source prover
#[cfg(has_binius_prover)]
mod ffi {
    use super::*;
    
    extern "C" {
        /// Simple FFI function that takes serialized data and returns serialized proof
        /// Returns the size of the proof on success, or negative error code on failure
        pub fn binius_prove(
            cs_bytes: *const u8,
            cs_len: usize,
            pub_witness_bytes: *const u8,
            pub_witness_len: usize,
            priv_witness_bytes: *const u8,
            priv_witness_len: usize,
            log_inv_rate: u32,
            proof_out: *mut u8,
            proof_capacity: usize,
        ) -> i32;
    }
    
    pub unsafe fn prove_serialized(
        cs_bytes: &[u8],
        pub_witness_bytes: &[u8],
        priv_witness_bytes: &[u8],
        log_inv_rate: u32,
    ) -> Result<Vec<u8>, ProverError> {
        // Allocate buffer for proof (generous size)
        let mut proof_buf = vec![0u8; 1024 * 1024]; // 1MB should be enough
        
        let result = binius_prove(
            cs_bytes.as_ptr(),
            cs_bytes.len(),
            pub_witness_bytes.as_ptr(),
            pub_witness_bytes.len(),
            priv_witness_bytes.as_ptr(),
            priv_witness_bytes.len(),
            log_inv_rate,
            proof_buf.as_mut_ptr(),
            proof_buf.capacity(),
        );
        
        if result < 0 {
            return Err(ProverError::from_ffi_code(result));
        }
        
        // Resize to actual proof size
        proof_buf.truncate(result as usize);
        Ok(proof_buf)
    }
}

