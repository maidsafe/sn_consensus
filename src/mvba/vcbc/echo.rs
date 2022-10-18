use crate::mvba::crypto::public::PubKey;

use super::context;
use super::deliver::DeliverState;
use super::message;
use super::message::Message;
use super::State;

pub(super) struct EchoState {
    pub ctx: context::Context,
}

impl State for EchoState {
    fn enter(mut self: Box<Self>) -> Box<dyn State> {
        let msg = Message {
            tag: message::MSG_TAG_ECHO.to_string(),
            proposal: self.context().proposal.as_ref().unwrap().clone(),
        };
        self.context_mut().broadcast(&msg);
        self.process_message(&self.context().cloned_self_key(), &msg);
        self.decide()
    }

    fn decide(self: Box<Self>) -> Box<dyn State> {
        if self.context().echos.len() >= self.context().super_majority_num() {
            let state = Box::new(DeliverState { ctx: self.ctx });
            state.enter()
        } else {
            self
        }
    }

    fn name(&self) -> String {
        "echo state".to_string()
    }

    fn context_mut(&mut self) -> &mut context::Context {
        &mut self.ctx
    }
    fn context(&self) -> &context::Context {
        &self.ctx
    }
}
