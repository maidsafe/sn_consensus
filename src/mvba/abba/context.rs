use super::{message::Message, message_set::MessageSet};
use crate::mvba::{broadcaster::Broadcaster, hash::Hash32};
use blsttc::{PublicKeySet, PublicKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub(super) struct Context {
    pub parties: PublicKeySet,
    pub number: usize,
    pub threshold: usize,
    pub proposal_id: Option<Hash32>,
    pub depot: HashMap<Hash32, MessageSet>,
    pub broadcaster: Rc<RefCell<Broadcaster>>,
    pub decided: bool,
}

impl Context {
    pub fn new(
        parties: PublicKeySet,
        number: usize,
        threshold: usize,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            parties,
            number,
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
        self.number - self.threshold
    }

    pub fn broadcast(&self, msg: &self::Message) {
        let data = msg.bytes().unwrap();
        self.broadcaster
            .borrow_mut()
            .push_message(super::MODULE_NAME, data);
    }

    pub fn cloned_self_key(&self) -> PublicKeyShare {
        self.broadcaster.borrow().self_key().clone()
    }
}
