use blsttc::PublicKeyShare;

use super::error::{Result};
use super::message::Message;
use super::message_set::MessageSet;
use super::{context};

use std::collections::hash_map::Entry;

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

    fn process_message(&mut self, _sender: &PublicKeyShare, msg: Message) -> Result<()> {
        match self.context_mut().depot.entry(msg.proposal_id.clone()) {
            Entry::Occupied(mut occ_entry) => occ_entry.get_mut().add_message(msg),
            Entry::Vacant(vac_ntry) => {
                let mut message_set = MessageSet::new();
                message_set.add_message(msg);
                vac_ntry.insert(message_set);
            }
        };

        todo!()
    }
}
