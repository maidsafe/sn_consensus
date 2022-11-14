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
        let buf = ([
            0x6F, 0x6F, 0x12, 0x94, 0x71, 0x59, 0x0D, 0x2C, 0x91, 0x80, 0x4C, 0x81, 0x2B, 0x57,
            0x50, 0xCD, 0x44, 0xCB, 0xDF, 0xB7, 0x23, 0x85, 0x41, 0xC4, 0x51, 0xE1, 0xEA, 0x2B,
            0xC0, 0x19, 0x31, 0x77,
        ]);
        assert_eq!(
            Hash32::calculate("abcd".as_bytes()).0.to_vec(),
            buf.to_vec()
        );
    }
}
