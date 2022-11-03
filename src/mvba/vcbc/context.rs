use blsttc::SecretKeyShare;

use super::error::Result;
use super::message::Message;
use crate::mvba::{broadcaster::Broadcaster, NodeId};
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap},
    rc::Rc,
};

pub(super) struct Context {
    pub number: usize,
    pub threshold: usize,
    pub id: String,             // this is same as $id$ in spec
    pub j: NodeId,              // this is same as $j$ in spec
    pub s: u32,                 // this is same as $s$ in spec
    pub m_bar: Option<Vec<u8>>, // this is same as $\bar{m}$ in spec
    pub u_bar: Option<Vec<u8>>, // this is same as $\bar{\mu}$ in spec
    pub wd: u32,                // this is same as $W_d$ in spec
    pub rd: u32,                // this is same as $r_d$ in spec
    pub message_log: HashMap<String, Vec<(NodeId, Message)>>,
    pub broadcaster: Rc<RefCell<Broadcaster>>,
    pub sec_key_share: SecretKeyShare,
    pub delivered: bool,
}

impl Context {
    pub fn new(
        number: usize,
        threshold: usize,
        id: String,
        j: NodeId,
        s: u32,
        broadcaster: Rc<RefCell<Broadcaster>>,
        sec_key_share: SecretKeyShare,
    ) -> Self {
        Self {
            number,
            threshold,
            id,
            j,
            s,
            m_bar: None,
            u_bar: None,
            wd: 0,
            rd: 0,
            message_log: HashMap::new(),
            broadcaster,
            sec_key_share,
            delivered: false,
        }
    }

    // super_majority_num simply return $n - t$.
    // There are $n$ parties, $t$ of which may be corrupted.
    // Protocol is reliable for $n > 3t$.
    pub fn super_majority_num(&self) -> usize {
        self.number - self.threshold
    }

    pub fn broadcast(&self, msg: &self::Message) {
        let data = bincode::serialize(msg).unwrap();
        self.broadcaster
            .borrow_mut()
            .broadcast(super::MODULE_NAME, data);
    }

    pub fn log_message(&mut self, sender: NodeId, msg: Message) -> Result<()> {
        if msg.id != self.id || msg.j != self.j || msg.s != self.s {
            log::warn!("ignoring suspicious message: {:?}. ", msg);
        }

        match self.message_log.entry(msg.action.clone()) {
            Entry::Occupied(mut occ_entry) => occ_entry.get_mut().push((sender, msg)),
            Entry::Vacant(vac_entry) => {
                let mut msg_vec = Vec::new();
                msg_vec.push((sender, msg));
                vac_entry.insert(msg_vec);
            }
        };
        Ok(())
    }
}
