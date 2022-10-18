use minicbor::to_vec;
use super::{
    error::{Error, Result},
    message::Message,
};
use crate::mvba::{
    broadcaster::Broadcaster,
    crypto::{hash::Hash32, public::PubKey},
    proposal::Proposal,
};
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap, HashSet},
    rc::Rc,
};

//TODO: better name, like context
pub(super) struct Context {
    pub parties: Vec<PubKey>,
    pub threshold: usize,
    pub proposer: PubKey,
    pub proposal: Option<Proposal>,
    pub echos: HashSet<PubKey>,
    pub broadcaster: Rc<RefCell<Broadcaster>>,
    pub delivered: bool,
}

impl Context {
    pub fn new(
        parties: &Vec<PubKey>,
        threshold: usize,
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
            delivered: false,
        }
    }

    // super_majority_num simply return $n - t$.
    // There are $n$ parties, $t$ of which may be corrupted.
    // Protocol is reliable for $n > 3t$.
    pub fn super_majority_num(&self) -> usize {
        self.parties.len() - self.threshold
    }

    // pub fn set_proposal(&mut self, proposal: Proposal) -> Result<()> {
    //     if proposal.proposer != self.proposer {
    //         return Err(Error::InvalidProposer(
    //             proposal.proposer,
    //             self.proposer.clone(),
    //         ));
    //     }
    //     if self.proposal.is_some() {
    //         return Err(Error::DuplicatedProposal(proposal));
    //     }
    //     self.proposal = Some(proposal);
    //     Ok(())
    // }

    pub fn broadcast(&mut self, msg: &self::Message) {
        let data = to_vec(msg).unwrap();
        self.broadcaster.borrow_mut().broadcast(data);
    }

    pub fn cloned_self_key(&self) -> PubKey {
        self.broadcaster.borrow().self_key().clone()
    }
}

