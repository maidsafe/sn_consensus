use super::{abba, mvba, tag::Domain, vcbc, NodeId};
use serde::{Deserialize, Serialize};

/// Bundle is a wrapper around the actual message
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Bundle<P> {
    /// This is the initiator node and in the most cases is same as `i` in specs.
    pub initiator: NodeId,
    /// This is the target node and in the most cases is same as `j` in specs.
    pub target: Option<NodeId>,
    /// This is the actual message
    pub(crate) message: Message<P>,
}

impl<P> Bundle<P> {
    pub fn domain(&self) -> &Domain {
        match &self.message {
            Message::Vcbc(msg) => &msg.tag.domain,
            Message::Mvba(msg) => &msg.vote.tag.domain,
            Message::Abba(msg) => &msg.tag.domain,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Message<P> {
    Vcbc(vcbc::message::Message<P>),
    Abba(abba::message::Message),
    Mvba(mvba::message::Message),
}

/// Ongoing messages definition
#[derive(Debug, Clone)]
pub enum Outgoing<P> {
    Gossip(Bundle<P>),
    Direct(NodeId, Bundle<P>),
}
