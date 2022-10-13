use thiserror::Error;

use crate::{crypto::public::PubKey, Proposal};

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid proposer. expected {0:?}, get {1:?}")]
    InvalidProposer(PubKey, PubKey),
    #[error("duplicated proposal. {0:?}")]
    DuplicatedProposal(Proposal),

}

pub type Result<T> = std::result::Result<T, Error>;
