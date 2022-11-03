use crate::mvba::{
    broadcaster::Broadcaster,
    proposal::Proposal,
    vcbc::{Vcbc},
    NodeId, ProposalChecker,
};
use blsttc::{PublicKeySet, SecretKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use super::bundle::Bundle;

pub struct Consensus {
    self_id: NodeId,
    threshold: usize,
    //_abba: Abba,
    vcbc_map: HashMap<NodeId, Vcbc>,
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl Consensus {
    pub fn init(
        bundle_id: u32,
        self_id: NodeId,
        sec_key_share: SecretKeyShare,
        pub_key_set: PublicKeySet,
        parties: Vec<NodeId>,
        threshold: usize,
        _proposal_checker: ProposalChecker,
    ) -> Consensus {
        let broadcaster = Broadcaster::new(bundle_id, &sec_key_share);
        let broadcaster_rc = Rc::new(RefCell::new(broadcaster));

        // TODO: uncomment me
        // let abba = Abba::new(
        //     pub_key_set.clone(),
        //     number,
        //     threshold,
        //     broadcaster_rc.clone(),
        // );
        let mut vcbc_map = HashMap::new();

        for id in &parties {
            let _pub_key = pub_key_set.public_key_share(id);
            let vcbc = Vcbc::new(
                parties.len(),
                threshold,
                self_id,
                "vcbc".to_string(),
                *id,
                0,
                broadcaster_rc.clone(),
                sec_key_share.clone(),
            );
            vcbc_map.insert(*id, vcbc).unwrap();
        }

        Consensus {
            self_id,
            threshold: pub_key_set.threshold(),
            vcbc_map,
            broadcaster: broadcaster_rc,
        }
    }

    // start the consensus by proposing a proposal and broadcasting it.
    pub fn start(&mut self, _proposal: Proposal) -> Vec<Vec<u8>> {
        log::debug!("starting {:?}", self.broadcaster.borrow().self_key());

        match self.vcbc_map.get_mut(&self.self_id) {
            Some(_vcbc) => {}
            None => {
                log::warn!("this node is an observer node")
            }
        }
        self.broadcaster.borrow_mut().take_bundles()
    }

    pub fn process_bundle(&mut self, sender: NodeId, bundle: &Bundle) -> Vec<Vec<u8>> {
        let mut delivered_count = 0;
        for vcbc in self.vcbc_map.values() {
            if vcbc.is_delivered() {
                delivered_count += 1;
            }
        }

        let vcbc = self.vcbc_map.get_mut(&sender).unwrap();
        let msg = bincode::deserialize(&bundle.message).unwrap();
        vcbc.process_message(sender, msg).unwrap();
        if delivered_count >= self.super_majority_num() {}

        self.broadcaster.borrow_mut().take_bundles()
    }

    fn super_majority_num(&self) -> usize {
        self.vcbc_map.len() - self.threshold
    }
}
