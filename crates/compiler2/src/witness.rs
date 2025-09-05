//! Witness variable types and management

use std::collections::HashMap;

/// A witness variable - corresponds to a wire in the constraint system
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum WitnessVar {
    /// Public input - deterministic from problem statement
    Public { id: u32 },
    
    /// Private input - supplied by prover
    Private { id: u32 },
    
    /// Auxiliary variable - computed internally
    /// The `eliminated` flag indicates if this was removed during optimization
    Auxiliary { id: u32, eliminated: bool },
    
    /// Constant value - always has a fixed value
    Constant { value: u64 },
}

impl WitnessVar {
    pub fn is_public(&self) -> bool {
        matches!(self, WitnessVar::Public { .. })
    }
    
    pub fn is_private(&self) -> bool {
        matches!(self, WitnessVar::Private { .. })
    }
    
    pub fn is_auxiliary(&self) -> bool {
        matches!(self, WitnessVar::Auxiliary { .. })
    }
    
    pub fn is_eliminated(&self) -> bool {
        matches!(self, WitnessVar::Auxiliary { eliminated: true, .. })
    }
    
    pub fn is_constant(&self) -> bool {
        matches!(self, WitnessVar::Constant { .. })
    }
    
    /// Get the unique ID for this variable (constants return u32::MAX)
    pub fn id(&self) -> u32 {
        match self {
            WitnessVar::Public { id } => *id,
            WitnessVar::Private { id } => *id + (1 << 20), // Offset to avoid collisions
            WitnessVar::Auxiliary { id, .. } => *id + (1 << 21),
            WitnessVar::Constant { .. } => u32::MAX,
        }
    }
}

/// Partial witness containing only input values
#[derive(Debug, Clone, Default)]
pub struct PartialWitness {
    public: HashMap<u32, u64>,
    private: HashMap<u32, u64>,
}

impl PartialWitness {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn set_public(&mut self, id: u32, value: u64) {
        self.public.insert(id, value);
    }
    
    pub fn set_private(&mut self, id: u32, value: u64) {
        self.private.insert(id, value);
    }
    
    pub fn get(&self, var: WitnessVar) -> Option<u64> {
        match var {
            WitnessVar::Public { id } => self.public.get(&id).copied(),
            WitnessVar::Private { id } => self.private.get(&id).copied(),
            WitnessVar::Constant { value } => Some(value),
            _ => None,
        }
    }
}

/// Complete witness including all computed values
#[derive(Debug, Clone)]
pub struct CompleteWitness {
    values: HashMap<WitnessVar, u64>,
}

impl CompleteWitness {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
    
    pub fn from_partial(partial: PartialWitness) -> Self {
        let mut values = HashMap::new();
        
        for (id, value) in partial.public {
            values.insert(WitnessVar::Public { id }, value);
        }
        
        for (id, value) in partial.private {
            values.insert(WitnessVar::Private { id }, value);
        }
        
        Self { values }
    }
    
    pub fn set(&mut self, var: WitnessVar, value: u64) {
        self.values.insert(var, value);
    }
    
    pub fn get(&self, var: WitnessVar) -> Option<u64> {
        match var {
            WitnessVar::Constant { value } => Some(value),
            _ => self.values.get(&var).copied(),
        }
    }
    
    pub fn has(&self, var: WitnessVar) -> bool {
        self.get(var).is_some()
    }
    
    /// Convert to constraint system witness vector
    /// Only includes non-eliminated witnesses
    pub fn to_constraint_witness(&self) -> Vec<u64> {
        let mut result = Vec::new();
        let mut vars: Vec<_> = self.values
            .keys()
            .filter(|v| !v.is_eliminated())
            .cloned()
            .collect();
        vars.sort();
        
        for var in vars {
            if let Some(value) = self.values.get(&var) {
                result.push(*value);
            }
        }
        
        result
    }
}

/// Tracks allocation of witness variables
#[derive(Debug, Clone)]
pub struct WitnessAllocator {
    next_public: u32,
    next_private: u32,
    next_auxiliary: u32,
}

impl WitnessAllocator {
    pub fn new() -> Self {
        Self {
            next_public: 0,
            next_private: 0,
            next_auxiliary: 0,
        }
    }
    
    pub fn new_public(&mut self) -> WitnessVar {
        let id = self.next_public;
        self.next_public += 1;
        WitnessVar::Public { id }
    }
    
    pub fn new_private(&mut self) -> WitnessVar {
        let id = self.next_private;
        self.next_private += 1;
        WitnessVar::Private { id }
    }
    
    pub fn new_auxiliary(&mut self) -> WitnessVar {
        let id = self.next_auxiliary;
        self.next_auxiliary += 1;
        WitnessVar::Auxiliary { id, eliminated: false }
    }
    
    pub fn constant(&self, value: u64) -> WitnessVar {
        WitnessVar::Constant { value }
    }
}