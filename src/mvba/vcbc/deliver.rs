use super::context;
use super::State;
use super::error::Result;

pub(super) struct DeliverState {
    pub ctx: context::Context
}

impl DeliverState {
    pub fn new(ctx: context::Context) -> Self {
        Self{ctx}
    }
}

impl State for DeliverState {
    fn enter(mut self: Box<Self>) -> Result<Box<dyn State>> {
        self.context_mut().delivered = true;
        Ok(self)
    }

    fn decide(self: Box<Self>) -> Result<Box<dyn State>> {
        Ok(self)
    }

    fn name(&self) -> String {
        "deliver state".to_string()
    }

    fn context_mut(&mut self) -> &mut context::Context {
        &mut self.ctx
    }
    fn context(&self) -> &context::Context{
        &self.ctx
    }
}
