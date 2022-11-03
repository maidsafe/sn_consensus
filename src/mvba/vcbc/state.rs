use super::context::Context;
use super::error::Result;
use super::message::Message;
use crate::mvba::NodeId;

pub(super) trait State {
    // enters to the new state
    fn enter(self: Box<Self>, ctx: &mut Context) -> Result<Box<dyn State>>;

    // process an incoming message from sender
    fn decide(&self, ctx: &mut Context) -> Result<Option<Box<dyn State>>>;

    fn name(&self) -> String;
}
