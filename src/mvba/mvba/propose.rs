use super::context::Context;
use super::echo::EchoState;
use super::error::Result;
use super::message::Message;
use super::State;

pub(super) struct ProposeState;

impl State for ProposeState {
    fn enter(self: Box<Self>, _: &mut Context) -> Result<Box<dyn State>> {
        Ok(self)
    }

    fn decide(&self, ctx: &mut Context) -> Result<Option<Box<dyn State>>> {
        match &ctx.proposal {
            Some(proposal) => {
                // Broadcast proposal if this party is the proposer
                if Some(proposal.proposer_id) == ctx.self_id() {
                    let msg = Message::Propose(proposal.clone());
                    ctx.broadcast(&msg);
                }
                let state = Box::new(EchoState);
                Ok(Some(state.enter(ctx)?))
            }
            None => Ok(None),
        }
    }

    fn name(&self) -> String {
        "propose state".to_string()
    }
}
