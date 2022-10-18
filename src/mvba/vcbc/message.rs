use minicbor::{Decode, Encode};
use crate::mvba::proposal::Proposal;


pub (super) const MSG_TAG_PROPOSE: &'static str = "v-propose";
pub (super) const MSG_TAG_ECHO: &'static str = "v-echo";

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub(crate) struct Message {
    #[n(1)]
    pub tag: String,
    #[n(2)]
    pub proposal: Proposal,
}
