use std::collections::BTreeMap;

use blsttc::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::{verify_sig, Generation, Proposition, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Decision<T: Proposition> {
    pub generation: Generation,
    pub proposals: BTreeMap<T, Signature>,
}

impl<T: Proposition> Decision<T> {
    pub fn validate(&self, public_key: &PublicKey) -> Result<()> {
        for (proposal, sig) in self.proposals.iter() {
            verify_sig(proposal, sig, public_key)?;
        }

        Ok(())
    }
}
