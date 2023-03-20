use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};

use crate::mvba::NodeId;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Domain {
    pub id: String, // the unique identifier of the domain, The domain used to differentiate the domains in the network.
    pub seq: usize, // represents the sequence number of the domain.
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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Tag {
    pub domain: Domain,   // The domain that is unique per consensus round
    pub proposer: NodeId, // the proposer unique identifier
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
