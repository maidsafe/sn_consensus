use blsttc::{Signature, SignatureShare};
use serde::{Serialize, Deserialize};



#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum MainVoteValue {
    One,
    Zero,
    Abstain
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq )]
pub enum PreVoteValue {
    One,
    Zero,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVoteAction {
    pub round: usize,
    pub value: PreVoteValue,
    pub justification: Signature,
    pub sig_share: SignatureShare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MainVoteAction {
    pub round: usize,
    pub value: MainVoteValue,
    pub justification: Signature,
    pub sig_share: SignatureShare,
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
