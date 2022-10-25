use super::context::Context;
use super::error::Result;
use super::State;

pub(super) struct DeliverState;

impl State for DeliverState {
    fn enter(self: Box<Self>, ctx: &mut Context) -> Result<Box<dyn State>> {
        ctx.delivered = true;
        Ok(self)
    }

    fn decide(&self, _ctx: &mut Context) -> Result<Option<Box<dyn State>>> {
        Ok(None)
    }
}