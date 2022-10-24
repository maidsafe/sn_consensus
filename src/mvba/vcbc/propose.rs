use super::context::Context;
use super::echo::EchoState;
use super::error::Result;
use super::message;
use super::message::Message;
use super::State;

pub(super) struct ProposeState;

impl State for ProposeState {
    fn enter(self: Box<Self>, ctx: &mut Context) -> Result<Box<dyn State>> {
        Ok(self)
    }

    fn decide(&self, ctx: &mut Context) -> Result<Option<Box<dyn State>>> {
        match &ctx.proposal {
            Some(proposal) => {
                let msg = Message {
                    tag: message::MSG_TAG_PROPOSE.to_string(),
                    proposal: proposal.clone(),
                };
                ctx.broadcast(&msg);
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
