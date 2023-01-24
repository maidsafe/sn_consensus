use super::{vcbc, NodeId};

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]

/// VoteMessage definition.
/// This is same as `v-vote` message in spec
pub struct VoteMessage {
    pub party: NodeId,                         // this is same as $a$ in spec
    pub value: bool,                           // this is same as $0$ or $1$ in spec
    pub proof: Option<vcbc::message::Message>, // this is same as $⊥$ or $ρ$ in spec
}
