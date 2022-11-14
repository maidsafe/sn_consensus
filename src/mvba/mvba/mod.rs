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
use super::{NodeId, ProposalChecker};
use crate::mvba::{broadcaster::Broadcaster, proposal::Proposal};

use std::cell::RefCell;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "vcbc";

// VCBC is a verifiably authenticatedly c-broadcast protocol.
// Each party $P_i$ c-broadcasts the value that it proposes to all other parties
// using verifiable authenticated consistent broadcast.
pub(crate) struct Vcbc {
    ctx: context::Context,
    state: Box<dyn State>,
}

impl Vcbc {
    pub fn new(
        number: usize,
        threshold: usize,
        proposer_id: NodeId,
        broadcaster: Rc<RefCell<Broadcaster>>,
        proposal_checker: ProposalChecker,
    ) -> Self {
        Self {
            ctx : context::Context::new(
                number,
                threshold,
                proposer_id,
                broadcaster,
                proposal_checker,
            ),
            state: Box::new(ProposeState),
        }
    }

    // propose sets the proposal and broadcast propose message.
    pub fn propose(&mut self, proposal: &Proposal) -> Result<()> {
        debug_assert_eq!(proposal.proposer_id, self.ctx.proposer_id);

        self.state.set_proposal(proposal, &mut self.ctx)?;
        if let Some(s) = self.state.decide(&mut self.ctx)? {
            self.state = s;
        }
        Ok(())
    }

    pub fn process_message(&mut self, sender: &NodeId, message: &[u8]) -> Result<()> {
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
