use blsttc::Signature;

use crate::Proposal;


pub struct Message {
    tag: String,
    proposal: Proposal,
    proof: Signature,
}
