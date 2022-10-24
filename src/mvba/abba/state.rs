use super::error::{Error, Result};
use super::{context, message};
use super::message::Message;
use crate::mvba::{crypto::public::PubKey, proposal::Proposal};

pub(super) trait State {
    // enters to the new state
    fn enter(self: Box<Self>) -> Result<Box<dyn State>>;

    // checks the context and decides to move to new state.
    fn decide(self: Box<Self>) -> Result<Box<dyn State>>;

    // return the name of the state
    fn name(&self) -> String;

    // returns the mutable version of context
    fn context_mut(&mut self) -> &mut context::Context;

    // returns the immutable version of context
    fn context(&self) -> &context::Context;



     fn process_message(&mut self, sender: &PubKey, msg: &Message) -> Result<()> {
        todo!()
    }
}
