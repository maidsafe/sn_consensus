use minicbor::{to_vec, Encode};

use super::crypto::public::{self, PubKey};

pub struct Broadcaster {
    self_key: PubKey,
    messages: Vec<Vec<u8>>,
}

impl Broadcaster {
    pub fn new(self_key: &PubKey) -> Self {
        Self {
            self_key: self_key.clone(),
            messages: Vec::new(),
        }
    }
    pub fn self_key(&self) -> &PubKey {
        &self.self_key
    }

    pub fn broadcast(&mut self, payload: Vec<u8>) {
        self.messages.push(payload)
    }
}
