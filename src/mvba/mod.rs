pub mod consensus;

mod abba;
mod bundle;
mod crypto;
mod doc;
mod vcbc;

use crypto::{hash::Hash, public::PubKey, signature::Signature};
use minicbor::{Decode, Encode, to_vec};


#[derive(Debug, Clone, Encode, Decode)]
pub struct Proposal {
    #[n(1)]
    proposer: PubKey,
    #[n(2)]
    value: Vec<u8>,
    #[n(3)]
    proof: Signature,
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

pub struct Broadcaster {
    messages: Vec<Vec<u8>>,
}

impl Broadcaster {
    pub fn new() -> Self {
        Self { messages: Vec::new() }
    }
    pub fn broadcast<'a, E:Encode>(&mut self, msg: E)  {
        let d = to_vec(msg).unwrap(); // todo: no unwrap
        self.messages.push(d)
    }

}
