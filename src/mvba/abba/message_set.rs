use super::message::Message;
use crate::mvba::crypto::public::PubKey;
use std::collections::HashMap;

pub(super) struct MessageSet {
    pre_process_messages: HashMap<PubKey, Message>,
}

impl MessageSet {
    pub fn new() -> Self {
        Self {
            pre_process_messages: HashMap::new(),
        }
    }

    pub fn add_message(&mut self, msg: Message) {
        todo!()
    }
}
