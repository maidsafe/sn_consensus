use crate::mvba::{hash, NodeId};
use core::fmt::Debug;
use thiserror::Error;

use super::{vcbc, abba};

#[derive(Error, Debug)]
pub enum Error {
    #[error("vcbc error {0:?}")]
    Vcbc(#[from] vcbc::error::Error),
    #[error("abba error {0:?}")]
    Abba(#[from] abba::error::Error),

    #[error("generic error {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;
