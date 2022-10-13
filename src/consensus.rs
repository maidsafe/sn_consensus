use crate::{
    abba::ABBA, crypto::public::PubKey, vcbc::VCBC, Proposal, ProposalChecker, ProposalService, Broadcaster,
};
use std::{collections::HashMap, rc::Rc, cell::RefCell};

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
        threshold: u32,
        proposal_checker: ProposalChecker,
        proposal: Proposal,
    ) -> Consensus {
        let abba = ABBA::new(); // TODO: Vec<> ???
        let mut vcbc_map = HashMap::new();

        let proposal_service = ProposalService::new(proposal, proposal_checker);
        let broadcaster = Rc::new(RefCell::new(Broadcaster::new()));

        for p in &parties {
            let  vcbc = VCBC::new( &p, &parties, threshold, &proposal_service, broadcaster.clone());
            vcbc_map.insert(p.clone(), vcbc).unwrap();
        }

        Consensus { id, self_key,abba, vcbc_map }
    }

    // start the consensus by proposing a proposal and broadcasting it.
    pub fn start(&mut self, proposal: Proposal) -> Vec<Vec<u8>> {

        let vcbc = self.vcbc_map.get_mut(&self.self_key).unwrap(); // TODO: no unwrap
        vcbc.set_proposal(proposal).unwrap();// TODO: no unwrap

        todo!()
    }

    pub fn process_bundle(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        todo!()
    }
}
