use super::context;
use super::State;

pub(super) struct DeliverState {
    pub ctx: context::Context
}

impl State for DeliverState {
    fn enter(mut self: Box<Self>) -> Box<dyn State> {
        self.context_mut().delivered = true;
        self
    }

    fn decide(self: Box<Self>) -> Box<dyn State> {
        self
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
