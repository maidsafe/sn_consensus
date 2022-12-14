use super::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub id: u32,
    pub sender: NodeId,
    pub module: String,   // TODO: use enum
    pub message: Vec<u8>, // TODO: use enum
}

/// Ongoing messages definition
pub enum Outgoing {
    Gossip(Bundle),
    Direct(NodeId, Bundle)
}
