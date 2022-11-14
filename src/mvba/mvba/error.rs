use crate::mvba::{proposal::Proposal, NodeId};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid proposer. expected {0:?}, get {1:?}")]
    InvalidProposer(NodeId, NodeId),
    #[error("invalid proposal: {0:?}")]
    InvalidProposal(Proposal),
    #[error("duplicated proposal: {0:?}")]
    DuplicatedProposal(Proposal),
    #[error("encoding/decoding error: {0}")]
    Encoding(String),
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Error::Encoding(format!("{}", err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
