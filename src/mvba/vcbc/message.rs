use serde::{Serialize, Deserialize};
use crate::mvba::proposal::Proposal;


pub (super) const MSG_TAG_PROPOSE: &'static str = "v-propose";
pub (super) const MSG_TAG_ECHO: &'static str = "v-echo";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Message {
    pub tag: String,
    pub proposal: Proposal,
}
