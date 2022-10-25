use blsttc::PublicKeyShare;

use super::error::{Error, Result};
use super::message::Message;
use super::{context, message};
use crate::mvba::proposal::Proposal;

pub(super) trait State {
    // enters to the new state
    fn enter(self: Box<Self>, ctx: &mut context::Context) -> Result<Box<dyn State>>;

    // checks the context and decides to move to new state.
    fn decide(&self, ctx: &mut context::Context) -> Result<Option<Box<dyn State>>>;

    // adds echo from the echoer for the context proposal
    fn add_echo(&mut self, echoer: &PublicKeyShare, ctx: &mut context::Context) {
        ctx.echos.insert(echoer.clone());
    }

    fn set_proposal(&mut self, proposal: &Proposal, ctx: &mut context::Context) -> Result<()> {
        if proposal.proposer != ctx.proposer {
            return Err(Error::InvalidProposer(
                proposal.proposer.clone(),
                ctx.proposer.clone(),
            ));
        }
        if let Some(context_proposal) = ctx.proposal.as_ref() {
            if context_proposal != proposal {
                return Err(Error::DuplicatedProposal(proposal.clone()));
            }
        }
        if !(ctx.proposal_checker)(proposal) {
            return Err(Error::InvalidProposal(proposal.clone()));
        }
        ctx.proposal = Some(proposal.clone());

        Ok(())
    }

    fn process_message(
        &mut self,
        sender: &PublicKeyShare,
        msg: &Message,
        ctx: &mut context::Context,
    ) -> Result<()> {
        match msg.tag.as_str() {
            message::MSG_TAG_PROPOSE => {
                self.set_proposal(&msg.proposal, ctx)?;
            }
            message::MSG_TAG_ECHO => {
                self.set_proposal(&msg.proposal, ctx)?;
                self.add_echo(sender, ctx);
            }
            _ => {}
        }

        Ok(())
    }
}
