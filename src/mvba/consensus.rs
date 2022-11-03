use crate::mvba::{
    broadcaster::Broadcaster, proposal::Proposal, vcbc::Vcbc, NodeId, ProposalChecker,
};
use blsttc::{PublicKeySet, SecretKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use super::bundle::Bundle;

pub struct Consensus {
    _id: u32,
    _number: usize,
    threshold: usize,
    //_abba: Abba,
    vcbc_map: HashMap<NodeId, Vcbc>,
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl Consensus {
    pub fn init(
        id: u32,
        secret_key: SecretKeyShare,
        pub_key_set: PublicKeySet,
        parties: Vec<NodeId>,
        number: usize,
        threshold: usize,
        proposal_checker: ProposalChecker,
    ) -> Consensus {
        let mut self_id = None;
        for id in &parties {
            let pub_key_share = pub_key_set.public_key_share(id);
            if secret_key.public_key_share().eq(&pub_key_share) {
                self_id = Some(*id);
                break;
            }
        }

        let broadcaster = Broadcaster::new(id, &secret_key, self_id);
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
                *id,
                broadcaster_rc.clone(),
                proposal_checker,
            );
            vcbc_map.insert(*id, vcbc).unwrap();
        }

        Consensus {
            _id: id,
            _number: number,
            threshold,
            vcbc_map,
            broadcaster: broadcaster_rc,
        }
    }

    // start the consensus by proposing a proposal and broadcasting it.
    pub fn start(&mut self, proposal: Proposal) -> Vec<Vec<u8>> {
        log::debug!("starting {:?}", self.broadcaster.borrow().self_key());

        match self.broadcaster.borrow().self_id() {
            Some(id) => {
                let vcbc = self.vcbc_map.get_mut(&id).unwrap(); // TODO: no unwrap
                vcbc.propose(&proposal).unwrap(); // TODO: no unwrap
                self.broadcaster.borrow_mut().take_bundles()
            }
            None => {
                log::debug!("we are not member of parties for this round");
                Vec::new()
            }
        }
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
        vcbc.process_message(&sender, &msg).unwrap();
        if delivered_count >= self.super_majority_num() {}

        self.broadcaster.borrow_mut().take_bundles()
    }

    fn super_majority_num(&self) -> usize {
        self.vcbc_map.len() - self.threshold
    }
}
