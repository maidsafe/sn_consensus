use blsttc::{Signature, SignatureShare};
use serde::{Deserialize, Serialize};

use crate::mvba::{hash::Hash32, tag::Tag};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum MainVoteValue {
    Value(bool),
    Abstain,
}

impl MainVoteValue {
    pub fn one() -> Self {
        Self::Value(true)
    }

    pub fn zero() -> Self {
        Self::Value(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum PreVoteJustification {
    // Round one without the justification. The initial value should set to zero
    FirstRoundZero,
    // with the weak validity. The initial value should set to one
    // The justification is a `c-final` signature of the VCBC protocol for this tuple:
    // `(id, proposer, 0, "c-ready", digest)`
    WithValidity(Hash32, Signature),
    // In Round r > 1, justification is either hard,...
    Hard(Signature),
    // ... or soft (refer to the spec)
    Soft(Signature),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum MainVoteJustification {
    // The justification consists of the justifications for the two conflicting pre-votes.
    Abstain(Box<PreVoteJustification>, Box<PreVoteJustification>),
    // The justification  is a valid S-threshold signature on value b ∈ {0, 1}
    NoAbstain(Signature),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PreVoteAction {
    pub round: usize,
    pub value: bool,
    pub justification: PreVoteJustification,
    pub sig_share: SignatureShare,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MainVoteAction {
    pub round: usize,
    pub value: MainVoteValue,
    pub justification: MainVoteJustification,
    pub sig_share: SignatureShare,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DecisionAction {
    pub round: usize,
    pub value: bool,
    pub sig: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Action {
    PreVote(PreVoteAction),
    MainVote(MainVoteAction),
    Decision(DecisionAction),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub tag: Tag, // this is same as $id.j.s$ in spec
    pub action: Action,
}

impl Message {
    pub fn action_str(&self) -> &str {
        match self.action {
            Action::PreVote(_) => "pre-vote",
            Action::MainVote(_) => "main-vote",
            Action::Decision(_) => "decision",
        }
    }
}
