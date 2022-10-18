use super::context;
use super::echo::EchoState;
use super::message::Message;
use super::State;
use super::{echo, message};

pub(super) struct ProposeState {
    pub ctx: context::Context,
}

impl State for ProposeState {
    fn enter(self: Box<Self>) -> Box<dyn State> {
        self
    }

    fn decide(mut self: Box<Self>) -> Box<dyn State> {
        match &self.context().proposal {
            Some(proposal) => {
                let msg = Message {
                    tag: message::MSG_TAG_PROPOSE.to_string(),
                    proposal: proposal.clone(),
                };
                self.context_mut().broadcast(&msg);
                let state = Box::new(EchoState { ctx: self.ctx });
                state.enter()
            }
            None => self,
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
