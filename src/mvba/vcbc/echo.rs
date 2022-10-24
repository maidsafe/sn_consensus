use super::context;
use super::deliver::DeliverState;
use super::error::Result;
use super::message;
use super::message::Message;
use super::State;

pub(super) struct EchoState;

impl State for EchoState {
    fn enter(mut self: Box<Self>, ctx: &mut context::Context) -> Result<Box<dyn State>> {
        let msg = Message {
            tag: message::MSG_TAG_ECHO.to_string(),
            proposal: ctx.proposal.as_ref().unwrap().clone(),
        };
        ctx.broadcast(&msg);
        self.process_message(&ctx.cloned_self_key(), &msg, ctx)?;
        match self.decide(ctx)? {
            Some(s) => Ok(s),
            None => Ok(self),
        }
    }

    fn decide(&self, ctx: &mut context::Context) -> Result<Option<Box<dyn State>>> {
        if ctx.echos.len() >= ctx.super_majority_num() {
            let state = Box::new(DeliverState);
            Ok(Some(state.enter(ctx)?))
        } else {
            Ok(None)
        }
    }

    fn name(&self) -> String {
        "echo state".to_string()
    }
}
