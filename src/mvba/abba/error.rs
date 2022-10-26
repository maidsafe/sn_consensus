use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    // TODO: try to use thiserror macro, like:
    // #[error("Failed to encode with bincode")]
    // Encoding(#[from] bincode::Error),
    //
    #[error("encoding/decoding error: {0}")]
    Encoding(String),
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Error::Encoding(format!("{}", err))
    }
}
pub type Result<T> = std::result::Result<T, Error>;
