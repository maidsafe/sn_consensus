use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, Signature};
use serde::{Deserialize, Serialize};

use crate::{verify_sig, Error, Fault, Generation, NodeId, Proposition, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Decision<T: Proposition> {
    pub generation: Generation,
    pub proposals: BTreeMap<T, Signature>,
    pub faults: BTreeSet<Fault<T>>,
}

impl<T: Proposition> Decision<T> {
    pub fn validate(&self, voters: &PublicKeySet) -> Result<()> {
        for (proposal, sig) in self.proposals.iter() {
            verify_sig(proposal, sig, &voters.public_key())?;
        }

        for fault in self.faults.iter() {
            fault.validate(voters).map_err(Error::FaultIsFaulty)?;
        }

        Ok(())
    }
    pub fn faulty_ids(&self) -> BTreeSet<NodeId> {
        BTreeSet::from_iter(self.faults.iter().map(Fault::voter_at_fault))
    }
}
