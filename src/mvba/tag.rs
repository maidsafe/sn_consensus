use std::fmt::{Debug, Display};

use crate::mvba::NodeId;

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Domain {
    pub id: String, // this is same as $ID$ in spec
    pub seq: usize, // this is same as $s$ in spec
}

impl Domain {
    pub fn new(id: impl Into<String>, seq: usize) -> Self {
        Self { id: id.into(), seq }
    }
}

impl Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}[{}]", self.id, self.seq)
    }
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Tag {
    pub domain: Domain,   // this is same as $ID.s$ in spec
    pub proposer: NodeId, // this is same as $j$ in spec
}

impl Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.domain, self.proposer)
    }
}

impl Debug for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Tag as Display>::fmt(self, f)
    }
}

impl Tag {
    pub fn new(domain: Domain, proposer: usize) -> Self {
        Self { domain, proposer }
    }
}
