use super::hash::Hash32;
use blsttc::PublicKeyShare;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub proposer: PublicKeyShare,
    pub value: Vec<u8>,
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
