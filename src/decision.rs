use std::collections::BTreeMap;

use blsttc::{PublicKeySet, Signature};
use serde::{Deserialize, Serialize};

use crate::{verify_sig, Generation, Proposition, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Decision<T: Proposition> {
    pub generation: Generation,
    pub proposals: BTreeMap<T, Signature>,
}

impl<T: Proposition> Decision<T> {
    pub fn validate(&self, voters: &PublicKeySet) -> Result<()> {
        for (proposal, sig) in self.proposals.iter() {
            verify_sig(proposal, sig, &voters.public_key())?;
        }

        Ok(())
    }
}
