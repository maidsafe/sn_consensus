use super::{
    error::{Error, Result},
    message::Message,
};
use crate::mvba::{crypto::public::PubKey, Broadcaster, Proposal};
use std::{collections::{HashMap, HashSet}, rc::Rc, cell::RefCell};

//TODO: better name, like context
pub struct Log {
    pub parties: Vec<PubKey>,
    pub threshold: u32,
    pub proposer: PubKey,
    pub proposal: Option<Proposal>,
    pub echos: HashSet<PubKey>,
    pub broadcaster: Rc<RefCell<Broadcaster>>,
}

struct MessageLog {}

impl Log {
    pub fn new(
        parties: &Vec<PubKey>,
        threshold: u32,
        proposer: &PubKey,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            parties: parties.clone(),
            threshold,
            proposer: proposer.clone(),
            proposal: None,
            echos: HashSet::new(),
            broadcaster,
        }
    }

    pub fn set_proposal(&mut self, proposal: Proposal) -> Result<()> {
        if proposal.proposer != self.proposer {
            return Err(Error::InvalidProposer(
                proposal.proposer,
                self.proposer.clone(),
            ));
        }
        if self.proposal.is_some() {
            return Err(Error::DuplicatedProposal(proposal));
        }
        self.proposal = Some(proposal);
        Ok(())
    }
}
