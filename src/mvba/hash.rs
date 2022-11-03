#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Hash32(pub [u8; 32]);

impl From<[u8; 32]> for Hash32 {
    fn from(val: [u8; 32]) -> Hash32 {
        Hash32(val)
    }
}

pub fn hash(d: &[u8]) -> Hash32 {
    use tiny_keccak::{Hasher, Sha3};

    let mut sha3 = Sha3::v256();
    let mut output = [0; 32];
    sha3.update(d);
    sha3.finalize(&mut output);
    Hash32::from(output)
}
