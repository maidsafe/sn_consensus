use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("encoding/decoding error {0:?}")]
    Encoding(#[from] bincode::Error),
    #[error("blsttc Error {0}")]
    Blsttc(#[from] blsttc::error::Error),
    #[error("invalid message {0}")]
    InvalidMessage(String),
    #[error("{0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;
