use super::error::Result;
use super::{
    bundle::{Bundle, Outgoing},
    consensus::ConsensusTrait,
    Proposal,
};

pub struct MockConsensus {
    pub decided_proposal: Option<Vec<u8>>,
}

impl MockConsensus {
    pub fn init() -> MockConsensus {
        MockConsensus {
            decided_proposal: None,
        }
    }
}

impl ConsensusTrait for MockConsensus {
    fn propose(&mut self, _: Proposal) -> Result<Vec<Outgoing>> {
        Ok(vec![])
    }

    fn process_bundle(&mut self, _: &Bundle) -> Result<Vec<Outgoing>> {
        Ok(vec![])
    }
}
