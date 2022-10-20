use super::message::Message;
use crate::mvba::{broadcaster::Broadcaster, crypto::public::PubKey, proposal::Proposal, ProposalChecker};
use minicbor::to_vec;
use std::{cell::RefCell, collections::HashSet, rc::Rc};

pub(super) struct Context {
    pub parties: Vec<PubKey>,
    pub threshold: usize,
    pub proposer: PubKey,
    pub proposal: Option<Proposal>,
    pub echos: HashSet<PubKey>,
    pub broadcaster: Rc<RefCell<Broadcaster>>,
    pub proposal_checker: Rc<RefCell<ProposalChecker>>,
    pub delivered: bool,
}

impl Context {
    pub fn new(
        parties: &Vec<PubKey>,
        threshold: usize,
        proposer: &PubKey,
        broadcaster: Rc<RefCell<Broadcaster>>,
        proposal_checker: Rc<RefCell<ProposalChecker>>
    ) -> Self {
        Self {
            parties: parties.clone(),
            threshold,
            proposer: proposer.clone(),
            proposal: None,
            echos: HashSet::new(),
            broadcaster,
            proposal_checker: proposal_checker.clone(),
            delivered: false,
        }
    }

    // super_majority_num simply return $n - t$.
    // There are $n$ parties, $t$ of which may be corrupted.
    // Protocol is reliable for $n > 3t$.
    pub fn super_majority_num(&self) -> usize {
        self.parties.len() - self.threshold
    }

    pub fn broadcast(&self, msg: &self::Message) {
        let data = to_vec(msg).unwrap();
        self.broadcaster.borrow_mut().push_message(data);
    }

    pub fn cloned_self_key(&self) -> PubKey {
        self.broadcaster.borrow().self_key().clone()
    }
}
