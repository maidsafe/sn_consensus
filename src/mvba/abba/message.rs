use super::error::Result;
use crate::mvba::hash::Hash32;
use minicbor::{Decode, Encode};

pub(super) const MSG_TAG_PRE_PROCESS: &'static str = "pre-process";

#[derive(Debug)]
pub(crate) struct Message {
    pub proposal_id: Hash32,
    pub tag: String,
    pub value: u8,
}

impl Message {
    pub fn decode(data: &[u8]) -> Result<Self> {
        todo!()
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        todo!()
    }
}
