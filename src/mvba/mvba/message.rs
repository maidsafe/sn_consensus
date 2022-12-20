use blsttc::{Signature, SignatureShare};
use serde::{Deserialize, Serialize};

use crate::mvba::Proposal;

use super::{NodeId};

/// VoteAction definition.
/// This is same as `v-vote` message in spec: (ID, v-vote, a, uj, ρj)
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Vote {
    pub proposer: NodeId,                     // this is same as $a$ in spec
    pub value: bool,                          // this is same as $0$ or $1$ in spec
    pub proof: Option<(Proposal, Signature)>, // this is same as $⊥$ or $ρ$ in spec
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Message {
    pub vote: Vote,
    pub voter: NodeId,
    pub signature: SignatureShare,
}
