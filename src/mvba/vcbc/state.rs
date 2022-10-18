use super::error::{Error, Result};
use super::{context, message};
use super::message::Message;
use crate::mvba::{crypto::public::PubKey, proposal::Proposal};

pub(super) trait State {
    // enters to the new state
    fn enter(self: Box<Self>) -> Box<dyn State>;
    // checks the context and decides to move to new state.
    fn decide(self: Box<Self>) -> Box<dyn State>;
    // return the name of the state
    fn name(&self) -> String;

    fn context_mut(&mut self) -> &mut context::Context;
    fn context(&self) -> &context::Context;
    //
    fn add_echo(&mut self, echoer: &PubKey) {
        self.context_mut().echos.insert(echoer.clone());
    }

    fn set_proposal(&mut self, proposal: &Proposal) -> Result<()> {
        if proposal.proposer != self.context().proposer {
            return Err(Error::InvalidProposer(
                proposal.proposer.clone(),
                self.context().proposer.clone(),
            ));
        }
        if let Some(context_proposal) = self.context().proposal.as_ref() {
            if context_proposal != proposal {
                return Err(Error::DuplicatedProposal(proposal.clone()));
            }
        }
        // if !(ctx.proposal_checker)(&proposal) {
        //     return Err(Error::InvalidProposal(proposal.clone()));
        // }
        self.context_mut().proposal = Some(proposal.clone());

        Ok(())
    }

     fn process_message(&mut self, sender: &PubKey, msg: &Message) -> Result<()> {
        match msg.tag.as_str() {
            message::MSG_TAG_PROPOSE => {
                self.set_proposal(&msg.proposal)?;
            }
            message::MSG_TAG_ECHO => {
                self.set_proposal(&msg.proposal)?;
                self.add_echo(&sender);
            }
            _ => {}
        }

        Ok(())
    }
}
