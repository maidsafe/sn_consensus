use crate::mvba::{
    abba::Abba, broadcaster::Broadcaster, crypto::public::PubKey, proposal::Proposal, vcbc::Vcbc,
    ProposalChecker,
};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub struct Consensus {
    id: u32,
    self_key: PubKey,
    abba: Abba,
    threshold: usize,
    vcbc_map: HashMap<PubKey, Vcbc>,
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl Consensus {
    pub fn init(
        id: u32,
        self_key: PubKey,
        parties: Vec<PubKey>,
        threshold: usize,
        proposal_checker: ProposalChecker,
    ) -> Consensus {
        let mut vcbc_map = HashMap::new();
        let broadcaster = Broadcaster::new(id, &self_key);
        let broadcaster_rc = Rc::new(RefCell::new(broadcaster));

        let abba = Abba::new(parties.clone(), threshold, broadcaster_rc.clone());

        for p in &parties {
            let vcbc = Vcbc::new(
                p.clone(),
                parties.clone(),
                threshold,
                broadcaster_rc.clone(),
                proposal_checker,
            );
            vcbc_map.insert(p.clone(), vcbc).unwrap();
        }

        Consensus {
            id,
            self_key,
            abba,
            threshold,
            vcbc_map,
            broadcaster: broadcaster_rc,
        }
    }

    // start the consensus by proposing a proposal and broadcasting it.
    pub fn start(&mut self, proposal: Proposal) -> Vec<Vec<u8>> {
        let vcbc = self.vcbc_map.get_mut(&self.self_key).unwrap(); // TODO: no unwrap
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
