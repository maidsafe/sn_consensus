pub(super) mod context;
mod deliver;
mod echo;
mod error;
pub(super) mod message;
mod propose;
pub(super) mod state;

use self::error::{Error, Result};
use self::message::Message;
use self::state::State;
use crate::mvba::crypto::public::PubKey;
use crate::mvba::{broadcaster::Broadcaster, proposal::Proposal};
use std::cell::RefCell;
use std::rc::Rc;

use super::ProposalChecker;

// VCBC is a verifiably authenticatedly c-broadcast protocol.
// Each party $P_i$ c-broadcasts the value that it proposes to all other parties
// using verifiable authenticated consistent broadcast.
pub(crate) struct VCBC {
    state: Option<Box<dyn State>>,
    proposal_checker: ProposalChecker,
}

impl VCBC {
    pub fn new(
        proposer: &PubKey,
        parties: &Vec<PubKey>,
        threshold: usize,
        proposal_checker: &ProposalChecker,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        let ctx = context::Context::new(parties, threshold, proposer, broadcaster);

        Self {
            state: Some(Box::new(propose::ProposeState { ctx })),
            proposal_checker: proposal_checker.clone(),
        }
    }

    fn decide(&mut self) {
        if let Some(s) = self.state.take() {
            self.state = Some(s.decide());
        }
    }

    // fn set_proposal(&mut self, proposal: &Proposal) -> Result<()> {
    //     if proposal.proposer != self.context.proposer {
    //         return Err(Error::InvalidProposer(
    //             proposal.proposer.clone(),
    //             self.context.proposer.clone(),
    //         ));
    //     }
    //     if let Some(context_proposal) = self.context.proposal.as_ref() {
    //         if context_proposal != proposal {
    //             return Err(Error::DuplicatedProposal(proposal.clone()));
    //         }
    //     }
    //     if !(self.proposal_checker)(&proposal) {
    //         return Err(Error::InvalidProposal(proposal.clone()));
    //     }
    //     self.context.proposal = Some(proposal.clone());

    //     Ok(())
    // }

    // propose sets the proposal and sent broadcast propose message.
    pub fn propose(&mut self, proposal: &Proposal) -> Result<()> {
        debug_assert_eq!(
            proposal.proposer,
            self.state.as_ref().unwrap().context().cloned_self_key()
        );

        if let Some(mut s) = self.state.take() {
            s.set_proposal(proposal)?;
            self.state = Some(s.decide());
        }
        Ok(())
    }

    pub fn is_delivered(&self) -> bool {
        self.state.as_ref().unwrap().context().delivered
    }

    pub fn process_message(&mut self, sender: &PubKey, payload: &[u8]) -> Result<()> {
        let msg: Message = minicbor::decode(payload)?;

        if let Some(mut s) = self.state.take() {
            s.process_message(sender, &msg)?;
            self.state = Some(s.decide());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
