use crate::{abba::ABBA, rbc::RBC, GossipService, Proposal, ProposalService};

struct Consensus<P: Proposal> {
    abba: ABBA<P>,
    rbc: RBC,
}

impl<P: Proposal> Consensus<P> {
    pub fn init(
        id: u32,
        gs: Box<dyn GossipService>,
        ps: Box<dyn ProposalService<P>>,
        parties: [u8],
        threshold: u32,
    ) -> Consensus<P> {
        let abba = ABBA::new();
        let rbc = RBC::new();
        Consensus {
            abba: abba,
            rbc: rbc,
        }
    }
}
