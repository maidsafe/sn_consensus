use super::context;
use super::echo::EchoState;
use super::error::Result;
use super::message;
use super::message::Message;
use super::State;

pub(super) struct ProposeState {
    pub ctx: context::Context,
}

impl ProposeState {
    pub fn new(ctx: context::Context) -> Self {
        Self{ctx}
    }
}

impl State for ProposeState {
    fn enter(self: Box<Self>) -> Result<Box<dyn State>> {
        Ok(self)
    }

    fn decide(self: Box<Self>) -> Result<Box<dyn State>> {
        match &self.context().proposal {
            Some(proposal) => {
                let msg = Message {
                    tag: message::MSG_TAG_PROPOSE.to_string(),
                    proposal: proposal.clone(),
                };
                self.context().broadcast(&msg);
                let state = Box::new(EchoState::new( self.ctx ));
                state.enter()
            }
            None => Ok(self),
        }
    }

    fn name(&self) -> String {
        "propose state".to_string()
    }

    fn context_mut(&mut self) -> &mut context::Context {
        &mut self.ctx
    }
    fn context(&self) -> &context::Context {
        &self.ctx
    }
}
