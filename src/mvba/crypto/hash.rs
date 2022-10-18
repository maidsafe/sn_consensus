#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Hash32([u8; 32]);



impl From<[u8; 32]> for Hash32 {
    fn from(val: [u8; 32]) -> Hash32 {
        Hash32(val)
    }
}