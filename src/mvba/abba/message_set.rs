use blsttc::PublicKeyShare;

use super::message::Message;
use std::collections::HashMap;

pub(super) struct MessageSet {
    pre_process_messages: HashMap<PublicKeyShare, Message>,
}

impl MessageSet {
    pub fn new() -> Self {
        Self {
            pre_process_messages: HashMap::new(),
        }
    }

    pub fn add_message(&mut self, _msg: Message) {
        todo!()
    }
}
