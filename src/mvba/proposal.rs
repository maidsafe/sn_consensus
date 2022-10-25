
use super::{hash::Hash32, crypto::public::PubKey};
use minicbor::{Decode, Encode, to_vec};


#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct Proposal {
    #[n(1)]
    pub proposer: PubKey,
    #[n(2)]
    pub value: Vec<u8>,
    #[n(3)]
    pub proof: Vec<u8>,
}


impl Proposal {
    pub fn hash(&self) -> Hash32 {
        use tiny_keccak::{Hasher, Sha3};

        let mut sha3 = Sha3::v256();
        let mut output = [0; 32];
        sha3.update(&self.value);
        sha3.finalize(&mut output);
        Hash32::from(output)
    }
}