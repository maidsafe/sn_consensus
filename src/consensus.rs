use crate::{
    abba::ABBA, crypto::public::PubKey, vcbc::VCBC, Proposal, ProposalChecker, ProposalService,
};
use std::collections::HashMap;

pub struct Consensus {
    id: u32,
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

        for p in &parties {
            let mut vcbc = VCBC::new(&self_key, &p, &parties, threshold, &proposal_service);
            vcbc.propose();
            vcbc_map.insert(p.clone(), vcbc).unwrap();
        }

        Consensus { id, abba, vcbc_map }
    }

    pub fn process_bundle(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        todo!()
    }
}
