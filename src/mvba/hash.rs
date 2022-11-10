use serde::{Deserialize, Serialize};
use thiserror::Error;

const HASH32_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash32([u8; HASH32_SIZE]);

#[derive(Error, Debug, Eq, PartialEq)]
#[error("invalid length: expected: {}, got: {}", .expected, .found)]
pub struct InvalidLength {
    expected: usize,
    found: usize,
}

impl Hash32 {
    pub fn calculate(data: &[u8]) -> Self {
        use tiny_keccak::{Hasher, Sha3};

        let mut sha3 = Sha3::v256();
        let mut hash = [0; HASH32_SIZE];
        sha3.update(data);
        sha3.finalize(&mut hash);
        Hash32(hash)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, InvalidLength> {
        let bytes: &[u8; HASH32_SIZE] = data.try_into().map_err(|_| InvalidLength {
            expected: HASH32_SIZE,
            found: data.len(),
        })?;
        Ok(Self(*bytes))
    }

    pub fn as_fixed_bytes(&self) -> &[u8; HASH32_SIZE] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(val: [u8; 32]) -> Self {
        Self(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoding() {
        assert!(Hash32::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_calc() {
        let buf = hex::decode("6F6F129471590D2C91804C812B5750CD44CBDFB7238541C451E1EA2BC0193177")
            .unwrap();
        assert_eq!(
            Hash32::calculate("abcd".as_bytes()).0.to_vec(),
            buf.to_vec()
        );
    }
}
