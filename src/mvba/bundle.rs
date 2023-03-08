use super::{abba, mvba, vcbc, NodeId};
use serde::{Deserialize, Serialize};

/// Bundle is a wrapper around the actual message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// This is the initiator node and in the most cases is same as `i` in specs.
    pub initiator: NodeId,
    /// This is the target node and in the most cases is same as `j` in specs.
    pub target: Option<NodeId>,
    /// This is the destination  module, it can be ABBA, VCBC or MVBA.
    pub module: String,
    /// This is the actual message
    pub(crate) message: Message,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Message {
    VcbcMsg(vcbc::message::Message),
    AbbaMsg(abba::message::Message),
    MvbaMsg(mvba::message::Message),
}

/// Ongoing messages definition
#[derive(Debug)]
pub enum Outgoing {
    Gossip(Bundle),
    Direct(NodeId, Bundle),
}
