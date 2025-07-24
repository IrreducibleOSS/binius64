pub mod uniqueness_propagator;

pub use uniqueness_propagator::{
    check_witness_uniqueness, process_circuit_uniqueness, UniquenessCheckResult,
    UniquenessPropagator, UniquenessReason, UniquenessStatus,
};