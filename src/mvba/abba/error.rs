use crate::mvba::{crypto::public::PubKey, proposal::Proposal};
use minicbor::{decode, encode};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid proposer. expected {0:?}, get {1:?}")]
    InvalidProposer(PubKey, PubKey),
    #[error("invalid proposal: {0:?}")]
    InvalidProposal(Proposal),
    #[error("duplicated proposal: {0:?}")]
    DuplicatedProposal(Proposal),
    #[error("decoding error: {0}")]
    Decode(String),
    #[error("encoding error: {0}")]
    Encode(String),
}

impl<W: std::fmt::Display> From<encode::Error<W>> for Error {
    fn from(err: encode::Error<W>) -> Self {
        Error::Encode(format!("{}", err))
    }
}

impl From<decode::Error> for Error {
    fn from(err: decode::Error) -> Self {
        Error::Decode(format!("{}", err))
    }
}
pub type Result<T> = std::result::Result<T, Error>;
