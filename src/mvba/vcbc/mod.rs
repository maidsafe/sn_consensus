pub(super) mod context;
pub(super) mod message;

mod error;

use self::error::{Error, Result};
use self::message::Message;
use super::{NodeId, ProposalChecker};
use crate::mvba::{broadcaster::Broadcaster, proposal::Proposal};

use std::cell::RefCell;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "vcbc";

#[derive(Debug)]
enum State {
    Propose,
    Echo,
    Deliver,
}

// VCBC is a verifiably authenticatedly c-broadcast protocol.
// Each party $P_i$ c-broadcasts the value that it proposes to all other parties
// using verifiable authenticated consistent broadcast.
pub(crate) struct Vcbc {
    ctx: context::Context,
    state: State,
}

impl Vcbc {
    pub fn new(
        parties: Vec<NodeId>,
        proposer_id: NodeId,
        threshold: usize,
        broadcaster: Rc<RefCell<Broadcaster>>,
        proposal_checker: ProposalChecker,
    ) -> Self {
        let ctx = context::Context::new(
            parties,
            threshold,
            proposer_id,
            broadcaster,
            proposal_checker,
        );

        Self {
            ctx,
            state: State::Propose,
        }
    }

    // propose sets the proposal and broadcast propose message.
    pub fn propose(&mut self, proposal: &Proposal) -> Result<()> {
        self.set_proposal(proposal)?;
        self.decide()
    }

    fn set_proposal(&mut self, proposal: &Proposal) -> Result<()> {
        if proposal.proposer_id != self.ctx.proposer_id {
            return Err(Error::InvalidProposer(
                self.ctx.proposer_id,
                proposal.proposer_id,
            ));
        }

        match self.ctx.proposal.as_ref() {
            Some(context_proposal) => {
                if context_proposal != proposal {
                    return Err(Error::DuplicatedProposal(proposal.clone()));
                }
            }
            None => {
                if !(self.ctx.proposal_checker)(proposal) {
                    return Err(Error::InvalidProposal(proposal.clone()));
                }
                self.ctx.proposal = Some(proposal.clone());
            }
        };
        Ok(())
    }

    pub fn decide(&mut self) -> Result<()> {
        match self.state {
            State::Propose => {
                if let Some(proposal) = &self.ctx.proposal {
                    // Broadcast proposal if this party is the proposer
                    if Some(proposal.proposer_id) == self.ctx.self_id() {
                        let msg = Message::Propose(proposal.clone());
                        self.ctx.broadcast(&msg);
                    }

                    self.state = State::Echo;

                    let msg = Message::Echo(proposal.clone());
                    self.ctx.broadcast(&msg);

                    if let Some(id) = &self.ctx.self_id() {
                        return self.process_message(id, msg);
                    } else {
                        return self.decide();
                    }
                }
            }
            State::Echo => {
                if self.ctx.echos.len() >= self.ctx.super_majority_num() {
                    self.state = State::Deliver;
                    self.ctx.delivered = true;
                }
            }
            State::Deliver => (),
        }
        Ok(())
    }

    pub fn process_message(&mut self, sender: &NodeId, msg: Message) -> Result<()> {
        log::debug!("{:?} processing message: {:?}", self.state, msg);

        if !self.ctx.parties.contains(sender) {
            return Err(Error::InvalidSender(*sender));
        }

        match msg {
            Message::Propose(proposal) => {
                self.set_proposal(&proposal)?;
            }
            Message::Echo(proposal) => {
                self.set_proposal(&proposal)?;
                self.ctx.echos.insert(*sender);
            }
        }

        self.decide()
    }

    pub fn is_delivered(&self) -> bool {
        self.ctx.delivered
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
