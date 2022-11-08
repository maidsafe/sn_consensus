use thiserror::Error;

const HASH32_SIZE: usize = 32;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
        let mut output = [0; 32];
        sha3.update(data);
        sha3.finalize(&mut output);
        Hash32::from_bytes(&output).unwrap()
    }

    fn from_fixed_bytes(val: [u8; 32]) -> Hash32 {
        Hash32(val)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, InvalidLength> {
        let bytes: &[u8; HASH32_SIZE] = data.try_into().map_err(|_| InvalidLength {
            expected: HASH32_SIZE,
            found: data.len(),
        })?;
        Ok(Self::from_fixed_bytes(*bytes))
    }

    pub fn as_fixed_bytes(&self) -> &[u8; HASH32_SIZE] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
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
        let buf = hex::decode("12b38977f2d67f06f0c0cd54aaf7324cf4fee184398ea33d295e8d1543c2ee1a")
            .unwrap();
        assert_eq!(
            Hash32::calculate("abcd".as_bytes()).0.to_vec(),
            buf.to_vec()
        );
    }
}
