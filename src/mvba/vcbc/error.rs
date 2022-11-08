use thiserror::Error;

use crate::mvba::hash;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("encoding/decoding error: {0}")]
    Encoding(String),
    #[error("Blsttc Error {0}")]
    Blsttc(#[from] blsttc::error::Error),
    #[error("Invalid hash length {0}")]
    InvalidHashLength(#[from] hash::InvalidLength),
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Error::Encoding(format!("{}", err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
