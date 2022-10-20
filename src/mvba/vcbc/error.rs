use minicbor::{decode, encode};
use thiserror::Error;
use crate::mvba::{crypto::public::PubKey, proposal::Proposal};

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid proposer. expected {0:?}, get {1:?}")]
    InvalidProposer(PubKey, PubKey),
    #[error("invalid proposal: {0:?}")]
    InvalidProposal(Proposal),
    #[error("duplicated proposal: {0:?}")]
    DuplicatedProposal(Proposal),
    #[error("decoding error: {0}")]
    DecodeError(String),
    #[error("encoding error: {0}")]
    EncodeError(String),

}

impl<W: std::fmt::Display> From<encode::Error<W>> for Error {
    fn from(err: encode::Error<W>) -> Self {
        Error::EncodeError(format!("{}", err))
    }
}

impl From<decode::Error> for Error {
    fn from(err: decode::Error) -> Self {
        Error::DecodeError(format!("{}", err))
    }
}
pub type Result<T> = std::result::Result<T, Error>;
