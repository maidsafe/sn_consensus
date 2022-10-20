use super::crypto::public::{PubKey};

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

    pub fn push_message(&mut self, data: Vec<u8>) {
        self.messages.push(data)
    }

    #[cfg(test)]
    pub fn has_message(&self, data: &Vec<u8>) -> bool {
        self.messages.contains(data)
    }
}
