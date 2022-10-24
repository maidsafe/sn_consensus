use super::context;
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
       todo!()
    }

    fn name(&self) -> String {
        "pre-process state".to_string()
    }

    fn context_mut(&mut self) -> &mut context::Context {
        &mut self.ctx
    }
    fn context(&self) -> &context::Context {
        &self.ctx
    }
}
