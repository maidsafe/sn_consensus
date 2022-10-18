use minicbor::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode)]
pub struct PubKey {
    #[n(1)]
    pub key: u32
}


pub fn RandomPubKey() -> PubKey {
    PubKey { key: rand::random() }
}