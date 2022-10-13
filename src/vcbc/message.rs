use crate::crypto::signature::Signature;
use minicbor::{Decode, Encode};
use crate::Proposal;


#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct Message {
    #[n(1)]
    pub tag: String,
    #[n(2)]
    pub proposal: Proposal,
}
