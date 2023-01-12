use core::fmt::Debug;
use thiserror::Error;

use super::{abba, mvba, vcbc};

#[derive(Error, Debug)]
pub enum Error {
    #[error("encoding/decoding error {0:?}")]
    Encoding(#[from] bincode::Error),
    #[error("vcbc error {0:?}")]
    Vcbc(#[from] vcbc::error::Error),
    #[error("vcbc error {0:?}")]
    Abba(#[from] abba::error::Error),
    #[error("abba {0}")]
    Mvba(#[from] mvba::error::Error),
    #[error("mvba error {0}")]
    InvalidMessage(String),
    #[error("generic error {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, Error>;
