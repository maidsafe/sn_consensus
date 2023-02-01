use std::fmt::Display;

use super::NodeId;

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Tag {
    pub domain: String,   // this is same as $id$ in spec
    pub proposer: NodeId, // this is same as $j$ in spec
    pub s: usize,         // this is same as $s$ in spec
}

impl Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.domain, self.proposer, self.s)
    }
}

impl Tag {
    pub fn new(domain: impl Into<String>, proposer: usize, s: usize) -> Self {
        Self {
            domain: domain.into(),
            proposer,
            s,
        }
    }
}
