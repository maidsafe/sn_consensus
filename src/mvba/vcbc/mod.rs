pub(super) mod context;
pub(super) mod message;
pub(super) mod state;

mod deliver;
mod echo;
mod error;
mod propose;

use self::error::Result;
use self::message::Message;
use self::propose::ProposeState;
use self::state::State;
use super::ProposalChecker;
use crate::mvba::{broadcaster::Broadcaster, proposal::Proposal};
use blsttc::{PublicKeySet, PublicKeyShare};
use std::cell::RefCell;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &'static str = "vcbc";

// VCBC is a verifiably authenticatedly c-broadcast protocol.
// Each party $P_i$ c-broadcasts the value that it proposes to all other parties
// using verifiable authenticated consistent broadcast.
pub(crate) struct VCBC {
    ctx: context::Context,
    state: Box<dyn State>,
}

impl VCBC {
    pub fn new(
        parties: PublicKeySet,
        proposer_index: usize,
        number: usize,
        threshold: usize,
        broadcaster: Rc<RefCell<Broadcaster>>,
        proposal_checker: ProposalChecker,
    ) -> Self {
        let ctx = context::Context::new(
            parties,
            number,
            threshold,
            proposer_index,
            broadcaster,
            proposal_checker,
        );

        Self {
            ctx,
            state: Box::new(ProposeState),
        }
    }

    // propose sets the proposal and broadcast propose message.
    pub fn propose(&mut self, proposal: &Proposal) -> Result<()> {
        debug_assert_eq!(proposal.proposer_index, self.ctx.proposer_index);

        self.state.set_proposal(proposal, &mut self.ctx)?;
        if let Some(s) = self.state.decide(&mut self.ctx)? {
            self.state = s;
        }
        Ok(())
    }

    pub fn process_message(&mut self, sender: &PublicKeyShare, message: &[u8]) -> Result<()> {
        let msg: Message = bincode::deserialize(message)?;

        self.state.process_message(sender, &msg, &mut self.ctx)?;
        if let Some(s) = self.state.decide(&mut self.ctx)? {
            self.state = s;
        }
        Ok(())
    }

    pub fn is_delivered(&self) -> bool {
        self.ctx.delivered
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
