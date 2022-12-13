use crate::mvba::{hash::Hash32, Proposal};
use blsttc::{Signature, SignatureShare};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Tag {
    pub id: String, // this is same as $id$ in spec
    pub j: usize,   // this is same as $j$ in spec
    pub s: usize,   // this is same as $s$ in spec
}

impl Tag {
    pub fn new(id: &str, j: usize, s: usize) -> Self {
        Self {
            id: id.to_string(),
            j,
            s,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Action {
    Send(Proposal),                // this is same as $c-send$ in spec
    Ready(Hash32, SignatureShare), // this is same as $c-ready$ in spec
    Final(Hash32, Signature),      // this is same as $c-final$ in spec
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
        }
    }
}
