use super::message::Message;
use crate::mvba::{broadcaster::Broadcaster, proposal::Proposal, NodeId, ProposalChecker};

use std::{cell::RefCell, collections::HashSet, rc::Rc};

pub(super) struct Context {
    pub parties: Vec<NodeId>,
    pub threshold: usize,
    pub proposer_id: NodeId,
    pub proposal: Option<Proposal>,
    pub echos: HashSet<NodeId>,
    pub broadcaster: Rc<RefCell<Broadcaster>>,
    pub proposal_checker: ProposalChecker,
    pub delivered: bool,
}

impl Context {
    pub fn new(
        parties: Vec<NodeId>,
        threshold: usize,
        proposer_id: NodeId,
        broadcaster: Rc<RefCell<Broadcaster>>,
        proposal_checker: ProposalChecker,
    ) -> Self {
        Self {
            parties,
            threshold,
            proposer_id,
            proposal: None,
            echos: HashSet::new(),
            broadcaster,
            proposal_checker,
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
        let data = bincode::serialize(msg).unwrap();
        self.broadcaster
            .borrow_mut()
            .push_message(super::MODULE_NAME, data);
    }

    pub fn self_id(&self) -> Option<NodeId> {
        self.broadcaster.borrow().self_id()
    }
}
