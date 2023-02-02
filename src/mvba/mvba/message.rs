use blsttc::{Signature, SignatureShare};
use serde::{Deserialize, Serialize};

use super::NodeId;
use crate::mvba::{hash::Hash32, tag::Tag};

/// VoteAction definition.
/// This is same as `v-vote` message in spec: (ID, v-vote, a, uj, ρj)
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Vote {
    pub tag: Tag,                           // this is same as $id.a.s$ in spec
    pub value: bool,                        // this is same as $0$ or $1$ in spec
    pub proof: Option<(Hash32, Signature)>, // this is same as $ρ$ in spec
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Message {
    pub vote: Vote,
    pub voter: NodeId,
    pub signature: SignatureShare,
}
