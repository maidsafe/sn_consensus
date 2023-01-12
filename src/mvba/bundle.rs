use super::NodeId;
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
    pub payload: Vec<u8>,
}

/// Ongoing messages definition
pub enum Outgoing {
    Gossip(Bundle),
    Direct(NodeId, Bundle),
}
