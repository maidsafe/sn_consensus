use std::fmt::Display;

use crate::mvba::{hash::Hash32, NodeId, Proposal};
use blsttc::{Signature, SignatureShare};

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

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Action {
    Send(Proposal),                // this is same as $c-send$ in spec
    Ready(Hash32, SignatureShare), // this is same as $c-ready$ in spec
    Final(Hash32, Signature),      // this is same as $c-final$ in spec
    Request,                       // this is same as $c-request$ in spec
    Answer(Proposal, Signature),   // this is same as $c-answer$ in spec
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub tag: Tag,
    pub action: Action,
}

impl Message {
    pub fn action_str(&self) -> &str {
        match self.action {
            Action::Send(_) => "c-send",
            Action::Ready(_, _) => "c-ready",
            Action::Final(_, _) => "c-final",
            Action::Request => "c-request",
            Action::Answer(_, _) => "c-answer",
        }
    }
}
