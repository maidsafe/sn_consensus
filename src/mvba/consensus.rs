use crate::mvba::{
    abba::ABBA, broadcaster::Broadcaster, crypto::public::PubKey, proposal::Proposal, vcbc::VCBC,
    ProposalChecker,
};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub struct Consensus {
    id: u32,
    self_key: PubKey,
    abba: ABBA,
    vcbc_map: HashMap<PubKey, VCBC>,
}

impl Consensus {
    pub fn init(
        id: u32,
        self_key: PubKey,
        parties: Vec<PubKey>,
        threshold: usize,
        proposal_checker: ProposalChecker,
    ) -> Consensus {
        let abba = ABBA::new(); // TODO: Vec<> ???
        let mut vcbc_map = HashMap::new();
        let broadcaster = Broadcaster::new(&self_key);
        let broadcaster = Rc::new(RefCell::new(broadcaster));

        for p in &parties {
            let vcbc = VCBC::new(
                &p,
                &parties,
                threshold,
                &proposal_checker,
                broadcaster.clone(),
            );
            vcbc_map.insert(p.clone(), vcbc).unwrap();
        }

        Consensus {
            id,
            self_key,
            abba,
            vcbc_map,
        }
    }

    // start the consensus by proposing a proposal and broadcasting it.
    pub fn start(&mut self, proposal: Proposal) -> Vec<Vec<u8>> {
        let vcbc = self.vcbc_map.get_mut(&self.self_key).unwrap(); // TODO: no unwrap
        vcbc.propose(&proposal).unwrap(); // TODO: no unwrap

        todo!()
    }

    pub fn process_bundle(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        todo!()
    }
}
