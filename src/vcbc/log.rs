use super::payload::Message;
use crate::{crypto::public::PubKey, Proposal};
use std::collections::{HashMap, HashSet};

pub struct Log {
    parties: Vec<PubKey>,
    message_log: MessageLog,
}

struct MessageLog {
    proposer: PubKey,
    proposal: Option<Proposal>,
    echos: HashSet<PubKey>,
}

impl Log {
    pub fn new(parties: &Vec<PubKey>, proposer: &PubKey) -> Self {
        Self {
            parties: parties.clone(),
            message_log: MessageLog {
                proposer: proposer.clone(),
                proposal: None,
                echos: HashSet::new(),
            },
        }
    }
}
