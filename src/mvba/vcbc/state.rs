use super::error::{Error, Result};
use super::message::Message;
use super::{context};
use crate::mvba::proposal::Proposal;
use crate::mvba::NodeId;


pub(super) trait State {
    // enters to the new state
    fn enter(self: Box<Self>, ctx: &mut context::Context) -> Result<Box<dyn State>>;

    // checks the context and decides to move to new state.
    fn decide(&self, ctx: &mut context::Context) -> Result<Option<Box<dyn State>>>;

    // adds echo from the echoer for the context proposal
    fn add_echo(&mut self, echoer: &NodeId, ctx: &mut context::Context) {
        ctx.echos.insert(*echoer);
    }

    fn name(&self) -> String;

    fn set_proposal(&mut self, proposal: &Proposal, ctx: &mut context::Context) -> Result<()> {
        if proposal.proposer_id != ctx.proposer_id {
            return Err(Error::InvalidProposer(
                ctx.proposer_id,
                proposal.proposer_id,
            ));
        }
        match ctx.proposal.as_ref() {
            Some(context_proposal) => {
                if context_proposal != proposal {
                    return Err(Error::DuplicatedProposal(proposal.clone()));
                }
            }
            None => {
                if !(ctx.proposal_checker)(proposal) {
                    return Err(Error::InvalidProposal(proposal.clone()));
                }
                ctx.proposal = Some(proposal.clone());
            }
        };

        Ok(())
    }

    fn process_message(
        &mut self,
        sender: &NodeId,
        msg: &Message,
        ctx: &mut context::Context,
    ) -> Result<()> {
        log::debug!("{} processing message: {:?}", self.name(), msg);

        if !ctx.parties.contains(sender) {
            return Err(Error::InvalidSender(*sender));
        }
        match msg {
            Message::Propose(proposal) => {
                self.set_proposal(proposal, ctx)?;
            }
            Message::Echo(proposal) => {
                self.set_proposal(proposal, ctx)?;
                self.add_echo(sender, ctx);
            }
            _ => {}
        }

        Ok(())
    }
}
