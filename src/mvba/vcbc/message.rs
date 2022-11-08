use blsttc::{Signature, SignatureShare};

use super::Tag;

pub(super) const MSG_ACTION_C_SEND: &str = "c-send";
pub(super) const MSG_ACTION_C_READY: &str = "c-ready";
pub(super) const MSG_ACTION_C_FINAL: &str = "c-final";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Sig {
    SignatureShare(SignatureShare),
    Signature(Signature),
    None,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub tag: Tag,
    pub action: String,
    pub m: Vec<u8>, // TODO: use serde trait
    pub sig: Sig,
}
