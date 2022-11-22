use crate::mvba::{hash, NodeId};
use core::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("encoding/decoding error {0:?}")]
    Encoding(#[from] bincode::Error),
    #[error("blsttc Error {0}")]
    Blsttc(#[from] blsttc::error::Error),
    #[error("invalid hash length {0}")]
    InvalidHashLength(#[from] hash::InvalidLength),
    #[error("duplicated message {0} from {1:?}")]
    DuplicatedMessage(NodeId, String),
    #[error("generic error {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;
