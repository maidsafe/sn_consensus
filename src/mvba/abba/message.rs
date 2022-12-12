use blsttc::{Signature, SignatureShare};
use serde::{Deserialize, Serialize};

use crate::mvba::vcbc::message::Tag;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum PreVoteValue {
    One,
    Zero,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum MainVoteValue {
    One,
    Zero,
    Abstain,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum PreVoteJustification {
    // Round one, without the justification. The initial value should set to zero
    FirstRoundZero,
    // Round one, with the justification. The initial value should set to one
    // The justification is `c-final` message of the VCBC protocol.
    FirstRoundOne(crate::mvba::vcbc::message::Message),
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
    pub value: PreVoteValue,
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
pub enum Action {
    PreVote(Box<PreVoteAction>),
    MainVote(Box<MainVoteAction>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub tag: Tag,
    pub action: Action,
}

impl Message {
    pub fn action_str(&self) -> &str {
        match self.action {
            Action::PreVote(_) => "pre-vote",
            Action::MainVote(_) => "pre-main",
        }
    }
}
