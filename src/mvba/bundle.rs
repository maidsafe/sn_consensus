use super::{NodeId, abba, vcbc};
use serde::{Deserialize, Serialize};

// TODO: remove me.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub enum BundleMessage {
//     Abba(abba::message::Message),
//     Vcbc(vcbc::message::Message),
// }


/// Bundle is a wrapper around the actual message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// This is the consensus ID and should be different per instance of MVBA
    pub id: String,
    /// This is the node if of the initiator and in the most cases is same as `j` in specs.
    pub initiator: NodeId,
    /// This is the destination  module, it can be ABBA, VCBC or MVBA.
    pub module: String,
    /// This is the actual message
    pub payload: Vec<u8>,
}

/// Ongoing messages definition
pub enum Outgoing {
    Gossip(Bundle),
    Direct(NodeId, Bundle)
}
