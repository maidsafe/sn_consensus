use std::fmt::Display;

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

impl Display for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for v in self.0 {
            f.write_str(&format!("{:02x}", v))?;
        }

        Ok(())
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
        let hash = Hash32::calculate("abcd".as_bytes());
        assert_eq!(
            format!("{}", hash),
            "6f6f129471590d2c91804c812b5750cd44cbdfb7238541c451e1ea2bc0193177"
        );
    }
}
