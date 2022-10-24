use super::{message::Message, message_set::MessageSet};
use crate::mvba::{broadcaster::Broadcaster, crypto::{public::PubKey, hash}, proposal::Proposal, ProposalChecker};
use minicbor::to_vec;
use std::{cell::RefCell, collections::{HashSet, HashMap}, rc::Rc};

pub(super) struct Context {
    pub parties: Vec<PubKey>,
    pub threshold: usize,
    pub proposal_id: Option<hash::Hash32>,
    pub depot: HashMap<hash::Hash32, MessageSet>,
    pub broadcaster: Rc<RefCell<Broadcaster>>,
    pub decided: bool,
}

impl Context {
    pub fn new(
        parties: &Vec<PubKey>,
        threshold: usize,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            parties: parties.clone(),
            threshold,
            proposal_id: None,
            depot: HashMap::new(),
            broadcaster,
            decided: false,
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
        self.broadcaster.borrow_mut().push_message("vcbc", data);
    }

    pub fn cloned_self_key(&self) -> PubKey {
        self.broadcaster.borrow().self_key().clone()
    }
}
