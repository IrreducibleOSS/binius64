// ffi.rs - FFI bindings to the closed-source prover

use std::os::raw::c_void;
use std::ptr::NonNull;

use crate::config::ProverConfig;
use crate::error::ProverError;
use crate::types::{Proof, Witness};

/// Opaque handle to the closed-source prover
pub struct ProverHandle {
    ptr: NonNull<c_void>,
}

// The prover handle is thread-safe
unsafe impl Send for ProverHandle {}
unsafe impl Sync for ProverHandle {}

impl ProverHandle {
    /// Create a new prover handle (using mock for now)
    pub fn create(_config: &ProverConfig) -> Result<Self, ProverError> {
        // For testing, use mock implementation
        #[cfg(not(feature = "closed-source"))]
        {
            let handle = unsafe { mock::create_prover(_config) };
            NonNull::new(handle)
                .map(|ptr| Self { ptr })
                .ok_or(ProverError::InitializationFailed)
        }
        
        // When closed-source feature is enabled, use real FFI
        #[cfg(feature = "closed-source")]
        {
            let handle = unsafe { ffi::prover_create(_config as *const ProverConfig) };
            NonNull::new(handle)
                .map(|ptr| Self { ptr })
                .ok_or(ProverError::InitializationFailed)
        }
    }

    /// Generate a proof
    pub fn prove(&self, witness: &Witness) -> Result<Proof, ProverError> {
        #[cfg(not(feature = "closed-source"))]
        {
            unsafe { mock::prove(self.ptr.as_ptr(), witness) }
        }
        
        #[cfg(feature = "closed-source")]
        {
            unsafe { ffi::prove(self.ptr.as_ptr(), witness) }
        }
    }
}

impl Drop for ProverHandle {
    fn drop(&mut self) {
        #[cfg(not(feature = "closed-source"))]
        unsafe {
            mock::destroy_prover(self.ptr.as_ptr());
        }
        
        #[cfg(feature = "closed-source")]
        unsafe {
            ffi::prover_destroy(self.ptr.as_ptr());
        }
    }
}

// Mock implementation for testing without closed-source binary
#[cfg(not(feature = "closed-source"))]
mod mock {
    use super::*;
    
    pub unsafe fn create_prover(_config: &ProverConfig) -> *mut c_void {
        // Return a non-null dummy pointer for testing
        Box::into_raw(Box::new(123u32)) as *mut c_void
    }
    
    pub unsafe fn prove(_handle: *mut c_void, witness: &Witness) -> Result<Proof, ProverError> {
        // Generate a mock proof based on witness length
        if witness.is_empty() {
            return Err(ProverError::InvalidWitness("Empty witness".to_string()));
        }
        
        // Create a simple mock proof
        let proof_size = (witness.len() * 32).min(1024);
        let proof_data = vec![0xFF; proof_size];
        Ok(Proof::from_bytes(&proof_data))
    }
    
    pub unsafe fn destroy_prover(handle: *mut c_void) {
        if !handle.is_null() {
            let _ = Box::from_raw(handle as *mut u32);
        }
    }
}

// Real FFI declarations (only when closed-source feature is enabled)
#[cfg(feature = "closed-source")]
mod ffi {
    use super::*;
    
    extern "C" {
        pub fn prover_create(config: *const ProverConfig) -> *mut c_void;
        pub fn prover_prove(handle: *mut c_void, witness: *const Witness) -> *mut Proof;
        pub fn prover_destroy(handle: *mut c_void);
    }
    
    pub unsafe fn prove(handle: *mut c_void, witness: &Witness) -> Result<Proof, ProverError> {
        let proof_ptr = prover_prove(handle, witness as *const Witness);
        if proof_ptr.is_null() {
            return Err(ProverError::ProverFailed("Proof generation failed".to_string()));
        }
        
        // Take ownership of the proof
        let proof = Box::from_raw(proof_ptr);
        Ok(*proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_handle_creation() {
        let config = ProverConfig::default();
        let handle = ProverHandle::create(&config);
        assert!(handle.is_ok());
    }
    
    #[test]
    fn test_handle_drop() {
        let config = ProverConfig::default();
        let handle = ProverHandle::create(&config).unwrap();
        drop(handle); // Should not panic
    }
    
    #[test]
    fn test_mock_prove() {
        let config = ProverConfig::default();
        let handle = ProverHandle::create(&config).unwrap();
        let witness = Witness::new(vec![1, 2, 3]);
        let proof = handle.prove(&witness);
        assert!(proof.is_ok());
        assert!(proof.unwrap().len() > 0);
    }
    
    #[test]
    fn test_empty_witness_fails() {
        let config = ProverConfig::default();
        let handle = ProverHandle::create(&config).unwrap();
        let witness = Witness::new(vec![]);
        let proof = handle.prove(&witness);
        assert!(proof.is_err());
    }
}