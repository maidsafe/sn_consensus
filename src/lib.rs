pub mod consensus;

mod abba;
mod bundle;
mod crypto;
mod doc;
mod vcbc;

use crypto::{hash::Hash, public::PubKey};

// trait GossipService {
//     fn broadcast_msg(msg: Serializable) -> Result<()>;
// }
//
// pub trait ProposalService<P: Proposal> {
//     fn get_proposal(&self) -> P;
//     fn check_proposal(&self, p: P) -> bool;
//     fn decided_proposal(&self, p: P);
// }

#[derive(Clone)]
pub struct Proposal {
    proposer: PubKey,
    value: Vec<u8>,
}

pub type ProposalChecker = fn(Proposal) -> bool;

pub struct ProposalService {
    proposal: Proposal,
    checker: ProposalChecker,
}

impl ProposalService {
    pub fn new(proposal: Proposal, checker: ProposalChecker) -> Self {
        Self { proposal, checker }
    }
    pub fn get_proposal(&self) -> &Proposal {
        &self.proposal
    }

    pub fn check_proposal(&self, p: &Proposal) -> bool {
        self.check_proposal(&p)
    }
}



impl Clone for ProposalService {
    fn clone(&self) -> Self {
        ProposalService {
            proposal: self.proposal.clone(),
            checker: self.checker,
        }
    }
}