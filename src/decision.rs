use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, Signature};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::{Error, Fault, Generation, NodeId, Proposition, Result, SignedVote, VoteCount};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Decision<T: Proposition> {
    pub votes: BTreeSet<SignedVote<T>>,
    pub proposals: BTreeMap<T, Signature>,
    pub faults: BTreeSet<Fault<T>>,
}

impl<T: Proposition> Decision<T> {
    pub fn validate(&self, voters: &PublicKeySet) -> Result<()> {
        let all_votes = self.votes_by_voter();
        let known_faulty_voters = self.faulty_ids();
        let expected_generation = self.generation()?;

        for vote in self.votes.iter() {
            vote.validate(voters, &Default::default())?;

            if vote.vote.gen != expected_generation {
                warn!("Not all votes in decision are from same generation");
                return Err(Error::InvalidDecision);
            }

            if let Err(faults) =
                vote.detect_byzantine_faults(voters, &all_votes, &Default::default())
            {
                let detected_faults = BTreeSet::from_iter(faults.into_keys());
                if !detected_faults.is_subset(&known_faulty_voters) {
                    warn!("Detected faulty voters who is not present in faults");
                    return Err(Error::InvalidDecision);
                }
            }
        }

        for fault in self.faults.iter() {
            fault.validate(voters).map_err(Error::FaultIsFaulty)?;
        }

        let vote_count = VoteCount::count(self.votes.iter().cloned(), &self.faulty_ids());
        if let Some(proposals) = vote_count.get_decision(voters)? {
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

    pub fn votes_by_voter(&self) -> BTreeMap<NodeId, SignedVote<T>> {
        let mut all_votes = BTreeMap::new();

        for vote in self.votes.iter().flat_map(|v| v.unpack_votes()) {
            let existing_vote = all_votes.entry(vote.voter).or_insert_with(|| vote.clone());

            if vote.supersedes(existing_vote) {
                all_votes.insert(vote.voter, vote.clone());
            }
        }

        all_votes
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
