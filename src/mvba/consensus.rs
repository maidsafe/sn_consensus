use crate::mvba::{
    broadcaster::Broadcaster, proposal::Proposal, vcbc::Vcbc, NodeId, ProposalChecker,
};
use blsttc::{PublicKeySet, SecretKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use super::{
    abba::{self, Abba},
    bundle::Bundle,
    vcbc::{self, message::Tag},
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
        _proposal_checker: ProposalChecker,
    ) -> Consensus {
        let broadcaster = Broadcaster::new(bundle_id, self_id, sec_key_share.clone());
        let broadcaster_rc = Rc::new(RefCell::new(broadcaster));

        // TODO: uncomment me
        // let abba = Abba::new(
        //     pub_key_set.clone(),
        //     number,
        //     threshold,
        //     broadcaster_rc.clone(),
        // );
        let mut abba_map = HashMap::new();
        let mut vcbc_map = HashMap::new();

        for id in &parties {
            let tag = Tag::new("vcbc", *id, 0);
            let vcbc = Vcbc::new(
                self_id,
                tag.clone(),
                pub_key_set.clone(),
                sec_key_share.clone(),
                broadcaster_rc.clone(),
            );
            vcbc_map.insert(*id, vcbc).unwrap();

            let abba = Abba::new(
                tag,
                self_id,
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

    // start the consensus by proposing a proposal and broadcasting it.
    pub fn start(&mut self, _proposal: Proposal) -> Vec<Vec<u8>> {
        match self.vcbc_map.get_mut(&self.self_id) {
            Some(_vcbc) => {}
            None => {
                log::warn!("this node is an observer node")
            }
        }

        // TODO:
        // self.broadcaster.borrow_mut().take_bundles()

        // TODO: fixme
        // just fixing cargo clippy issees
        match self.abba_map.get_mut(&self.self_id) {
            Some(abba) => {
                let c_final = vcbc::message::Message {
                    tag: vcbc::message::Tag::new("id", 0, 0),
                    action: vcbc::message::Action::Send(vec![]),
                };
                abba.pre_vote_one(c_final).unwrap();
                abba.pre_vote_zero().unwrap();
                abba.is_decided();
            }
            None => {
                log::warn!("this node is an observer node")
            }
        }
        vec![]
    }

    pub fn process_bundle(&mut self, sender: NodeId, bundle: &Bundle) -> Vec<Vec<u8>> {
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
        // TODO:
        // self.broadcaster.borrow_mut().take_bundles()
        vec![]
    }

    fn super_majority_num(&self) -> usize {
        self.vcbc_map.len() - self.threshold
    }
}
