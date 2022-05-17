use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, Signature};

use crate::{Error, Fault, Generation, NodeId, Proposition, Result, SignedVote};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<T: Proposition> {
    pub votes: BTreeSet<SignedVote<T>>,
    pub proposals: BTreeMap<T, Signature>,
    pub faults: BTreeSet<Fault<T>>,
}

impl<T: Proposition> Decision<T> {
    pub fn validate(&self, voters: &PublicKeySet) -> Result<()> {
        let proposals = BTreeSet::from_iter(self.proposals.keys());
        for vote in self.votes.iter() {
            vote.validate_signature(voters)?;
            let count = vote.vote_count();
        }

        Ok(())
    }

    pub fn faulty_ids(&self) -> BTreeSet<NodeId> {
        BTreeSet::from_iter(self.faults.iter().map(Fault::voter_at_fault))
    }

    /// Returns the generation of this decision.
    /// Assumes that Decision::validate() has already been checked.
    pub fn generation(&self) -> Result<Generation> {
        match self.votes.iter().next() {
            Some(vote) => Ok(vote.vote.gen),
            None => Err(Error::DecisionHasNoVotes),
        }
    }
}
