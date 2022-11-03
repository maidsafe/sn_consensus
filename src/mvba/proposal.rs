use super::hash::{hash, Hash32};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub proposer_id: usize,
    pub value: Vec<u8>,
    pub proof: Vec<u8>,
}

impl Proposal {
    pub fn hash(&self) -> Hash32 {
        hash(&self.value)
    }
}
