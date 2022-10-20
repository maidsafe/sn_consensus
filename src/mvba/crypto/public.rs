use minicbor::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode)]
pub struct PubKey {
    #[n(1)]
    pub key: u32
}

#[cfg(test)]
pub fn random_pub_key() -> PubKey {
    PubKey { key: rand::random() }
}