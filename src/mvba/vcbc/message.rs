use crate::mvba::{hash::Hash32, tag::Tag};
use blsttc::{Signature, SignatureShare};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Action<P> {
    Send(P),                       // this is same as $c-send$ in spec
    Ready(Hash32, SignatureShare), // this is same as $c-ready$ in spec
    Final(Hash32, Signature),      // this is same as $c-final$ in spec
    Request,                       // this is same as $c-request$ in spec
    Answer(P, Signature),          // this is same as $c-answer$ in spec
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Message<P> {
    pub tag: Tag,
    pub action: Action<P>,
}

impl<P> Message<P> {
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
