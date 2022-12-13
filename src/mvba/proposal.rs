use super::hash::Hash32;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub value: Vec<u8>,
    pub proof: Vec<u8>,
}
