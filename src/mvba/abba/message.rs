use blsttc::{Signature, SignatureShare};
use serde::{Deserialize, Serialize};

use crate::mvba::hash::Hash32;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum MainVoteValue {
    One,
    Zero,
    Abstain,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum PreVoteValue {
    One,
    Zero,
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum PreVoteVoteJustification {
    // In round r = 1, justification is the validity of the subject data
    RoundOneJustification(Hash32, Signature),
    // In Round r > 1, justification is either hard,...
    HardJustification(Signature),
    // ... or soft (refer to the spec)
    SoftJustification(Signature),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum MainVoteJustification {
    // The justification consists of the justifications for the two conflicting pre-votes.
    AbstainJustification(Signature, Signature),
    // The justification  is a valid S-threshold signature on value b ∈ {0, 1}
    NoAbstainJustification(Signature),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVoteAction {
    pub round: usize,
    pub value: PreVoteValue,
    pub sig_share: SignatureShare,
    pub justification: PreVoteVoteJustification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MainVoteAction {
    pub round: usize,
    pub value: MainVoteValue,
    pub sig_share: SignatureShare,
    pub justification: MainVoteJustification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    PreVote(PreVoteAction),
    MainVote(MainVoteAction),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
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
