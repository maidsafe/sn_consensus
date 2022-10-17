mod deliver;
mod echo;
mod error;
pub mod log;
mod message;
mod propose;

use std::cell::RefCell;
use std::rc::Rc;

use self::error::{Error, Result};
use self::message::Message;
use crate::mvba::{crypto::public::PubKey, ProposalService};
use crate::mvba::{Broadcaster, Proposal};

pub trait State {

    fn enter(self: Box<Self>, log: &mut log::Log) -> Box<dyn State>;
    // check the log and decide to move to new state.
    fn decide(self: Box<Self>, log: &mut log::Log) -> Box<dyn State>;
    // the name of current state.
    fn name(&self) -> String;
}

// VCBC is a verifiably authenticatedly c-broadcast protocol.
// Each party $P_i$ c-broadcasts the value that it proposes to all other parties
// using verifiable authenticated consistent broadcast.
pub struct VCBC {
    log: log::Log,
    state: Option<Box<dyn State>>,
    proposal_service: ProposalService,
}

impl VCBC {
    pub fn new(
        proposer: &PubKey,
        parties: &Vec<PubKey>,
        threshold: u32,
        proposal_service: &ProposalService,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            log: log::Log::new(parties, threshold, proposer, broadcaster),
            state: Some(Box::new(propose::ProposeState{})),
            proposal_service: proposal_service.clone(),
        }
    }

    fn decide(&mut self) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.decide(&mut self.log));
        }
    }

    pub fn set_proposal(&mut self, proposal: Proposal) -> Result<()> {
        if proposal.proposer != self.log.proposer {
            return Err(Error::InvalidProposer(
                proposal.proposer,
                self.log.proposer.clone(),
            ));
        }
        if self.log.proposal.is_some() {
            return Err(Error::DuplicatedProposal(proposal));
        }

        self.log.proposal = Some(proposal);
        self.decide();

        Ok(())
    }

    pub fn process_message(&mut self, msg: &Message) -> Box<dyn State> {
        todo!()
    }
}
