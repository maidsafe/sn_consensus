use crate::Result;

pub trait Proposal {
    fn validate(&self) -> Result<()>;
}
