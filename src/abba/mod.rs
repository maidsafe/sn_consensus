use crate::{GossipService, Proposal, ProposalService};

mod log;

pub struct ABBA<P: Proposal> {
    log: log::Log,
    gossip_service: Box<dyn GossipService>,
    proposal_service: Box<dyn ProposalService<P>>,
}

impl<P: Proposal> ABBA<P> {
    pub fn new() -> Self {
        todo!()
    }
}
