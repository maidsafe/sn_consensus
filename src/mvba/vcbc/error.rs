use crate::mvba::hash;
use core::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("encoding/decoding error")]
    Encoding(#[from] bincode::Error),
    #[error("Blsttc Error {0}")]
    Blsttc(#[from] blsttc::error::Error),
    #[error("Invalid hash length {0}")]
    InvalidHashLength(#[from] hash::InvalidLength),
}

pub type Result<T> = std::result::Result<T, Error>;
