use crate::mvba::{
    abba::Abba, broadcaster::Broadcaster, proposal::Proposal, vcbc::VCBC, ProposalChecker,
};
use blsttc::{PublicKeySet, PublicKeyShare, SecretKeyShare};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub struct Consensus {
    id: u32,
    number: usize,
    threshold: usize,
    self_key_index: usize,
    abba: Abba,
    vcbc_map: HashMap<usize, VCBC>, // Mapping proposer_index to VCBC instance
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl Consensus {
    pub fn init(
        id: u32,
        secret_key: SecretKeyShare,
        parties: PublicKeySet,
        number: usize,
        threshold: usize,
        proposal_checker: ProposalChecker,
    ) -> Consensus {
        let mut vcbc_map = HashMap::new();
        let broadcaster = Broadcaster::new(id, &secret_key);
        let broadcaster_rc = Rc::new(RefCell::new(broadcaster));

        let mut self_key_index = usize::MAX;
         for index in 0..number {
            let pub_key_share = parties.public_key_share(index);
            if secret_key.public_key_share().eq(&pub_key_share) {
                self_key_index = index;
                break;
            }
        };

        if self_key_index == usize::MAX {
            // TODO: return error: no panic
            panic!("invalid secret key share")
            //return
        }

        let abba = Abba::new(parties.clone(), number, threshold, broadcaster_rc.clone());

        for index in 0..number {
            let vcbc = VCBC::new(
                parties.clone(),
                index,
                number,
                threshold,
                broadcaster_rc.clone(),
                proposal_checker,
            );
            vcbc_map.insert(index, vcbc).unwrap();
        }

        Consensus {
            id,
            abba,
            number,
            self_key_index,
            threshold,
            vcbc_map,
            broadcaster: broadcaster_rc,
        }
    }

    // start the consensus by proposing a proposal and broadcasting it.
    pub fn start(&mut self, proposal: Proposal) -> Vec<Vec<u8>> {
        // TODO: Keep self_key as ammber of consensus if we need it in other places....
        let vcbc = self
            .vcbc_map
            .get_mut(&self.self_key_index)
            .unwrap(); // TODO: no unwrap
        vcbc.propose(&proposal).unwrap(); // TODO: no unwrap

        self.broadcaster.borrow_mut().take_bundles()
    }

    pub fn process_bundle(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut delivered_count = 0;
        for vcbc in self.vcbc_map.values() {
            if vcbc.is_delivered() {
                delivered_count += 1;
            }
        }

        if delivered_count >= self.super_majority_num() {}

        self.broadcaster.borrow_mut().take_bundles()
    }

    fn super_majority_num(&self) -> usize {
        self.vcbc_map.len() - self.threshold
    }
}
