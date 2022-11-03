use crate::mvba::NodeId;

pub(super) const MSG_ACTION_C_BROADCAST: &str = "c-broadcast";
pub(super) const MSG_ACTION_C_SEND: &str = "c-send";
pub(super) const MSG_ACTION_C_READY: &str = "c-ready";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub id: String,
    pub j: NodeId,
    pub s: u32,
    pub action: String,
    pub m: Vec<u8>,           // TODO: use serde trait
    pub sig: Option<Vec<u8>>, // Signature share or threshold signature
}
