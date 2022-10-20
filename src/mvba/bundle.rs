use minicbor::{Decode, Encode};

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct Bundle {
    #[n(1)]
    pub id: u32,
    #[n(2)]
    pub module: String,
    #[n(3)]
    pub message: Vec<u8>,
}
