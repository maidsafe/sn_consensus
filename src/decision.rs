use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, Signature};
use log::warn;

use crate::{Error, Fault, Generation, NodeId, Proposition, Result, SignedVote, VoteCount};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<T: Proposition> {
    pub votes: BTreeSet<SignedVote<T>>,
    pub proposals: BTreeMap<T, Signature>,
    pub faults: BTreeSet<Fault<T>>,
}

impl<T: Proposition> Decision<T> {
    pub fn validate(&self, voters: &PublicKeySet) -> Result<()> {
        for vote in self.votes.iter() {
            vote.validate(voters, &Default::default())?;
        }

        for fault in self.faults.iter() {
            fault.validate(voters).map_err(Error::FaultIsFaulty)?;
        }

        if let Some(proposals) =
            VoteCount::count(self.votes.iter().cloned(), &self.faulty_ids()).get_decision(voters)?
        {
            if proposals != self.proposals {
                warn!("Proposals from votes does not match decision proposals");
                return Err(Error::InvalidDecision);
            }
        } else {
            warn!("Votes in decision don't form a decision");
            return Err(Error::InvalidDecision);
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
