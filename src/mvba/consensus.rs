use crate::mvba::{broadcaster::Broadcaster, vcbc::Vcbc, MessageValidity, NodeId};
use blsttc::{PublicKeySet, SecretKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use super::{
    abba::{self, Abba},
    bundle::{Bundle, Outgoing},
    error::{Error, Result},
    vcbc::{self, message::Tag},
    Proposal,
};

pub struct Consensus {
    self_id: NodeId,
    threshold: usize,
    abba_map: HashMap<NodeId, Abba>,
    vcbc_map: HashMap<NodeId, Vcbc>,
    #[allow(unused)]
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl Consensus {
    pub fn init(
        bundle_id: u32,
        self_id: NodeId,
        sec_key_share: SecretKeyShare,
        pub_key_set: PublicKeySet,
        parties: Vec<NodeId>,
        message_validity: MessageValidity,
    ) -> Consensus {
        let broadcaster = Broadcaster::new(bundle_id, self_id);
        let broadcaster_rc = Rc::new(RefCell::new(broadcaster));
        let mut abba_map = HashMap::new();
        let mut vcbc_map = HashMap::new();

        for id in &parties {
            let tag = Tag::new("vcbc", *id, 0);
            let vcbc = Vcbc::new(
                self_id,
                tag.clone(),
                pub_key_set.clone(),
                sec_key_share.clone(),
                message_validity,
                broadcaster_rc.clone(),
            );
            vcbc_map.insert(*id, vcbc).unwrap();

            let abba = Abba::new(
                format!("{}", id),
                self_id,
                tag,
                pub_key_set.clone(),
                sec_key_share.clone(),
                broadcaster_rc.clone(),
            );
            abba_map.insert(*id, abba).unwrap();
        }

        Consensus {
            self_id,
            threshold: pub_key_set.threshold(),
            vcbc_map,
            abba_map,
            broadcaster: broadcaster_rc,
        }
    }

    /// starts the consensus by broadcasting the `m`.
    pub fn start(&mut self, proposal: Proposal) -> Result<Vec<Outgoing>> {
        match self.vcbc_map.get_mut(&self.self_id) {
            Some(vcbc) => {
                vcbc.c_broadcast(proposal)?;
            }
            None => {
                log::warn!("this node is an observer node")
            }
        }
        Ok(self.broadcaster.borrow_mut().take_outgoings())
    }

    pub fn process_bundle(&mut self, sender: NodeId, bundle: &Bundle) -> Result<Vec<Outgoing>> {
        let mut delivered_count = 0;
        for vcbc in self.vcbc_map.values() {
            if vcbc.is_delivered() {
                delivered_count += 1;
            }
        }

        match bundle.module.as_ref() {
            vcbc::MODULE_NAME => {
                let vcbc = self.vcbc_map.get_mut(&sender).unwrap();
                let msg = bincode::deserialize(&bundle.message).unwrap();
                vcbc.receive_message(sender, msg).unwrap();
                if delivered_count >= self.super_majority_num() {}
            }
            abba::MODULE_NAME => {
                let abba = self.abba_map.get_mut(&sender).unwrap();
                let msg = bincode::deserialize(&bundle.message).unwrap();
                abba.receive_message(sender, msg).unwrap();
                if delivered_count >= self.super_majority_num() {}
            }
            _ => {
                //
            }
        }
        Ok(self.broadcaster.borrow_mut().take_outgoings())
    }

    fn super_majority_num(&self) -> usize {
        self.vcbc_map.len() - self.threshold
    }
}
