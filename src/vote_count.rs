use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
};

use blsttc::{PublicKeySet, Signature, SignatureShare};

use crate::{Ballot, NodeId, Proposition, Result, SignedVote};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Candidate<T> {
    pub proposals: BTreeSet<T>,
    pub faulty: BTreeSet<NodeId>,
}

impl<T> Default for Candidate<T> {
    fn default() -> Self {
        Self {
            proposals: Default::default(),
            faulty: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperMajorityCount<T> {
    pub count: usize,
    pub proposals: BTreeMap<T, BTreeMap<u64, SignatureShare>>,
}

impl<T> Default for SuperMajorityCount<T> {
    fn default() -> Self {
        Self {
            count: 0,
            proposals: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteCount<T> {
    pub candidates: BTreeMap<Candidate<T>, usize>,
    pub super_majorities: BTreeMap<Candidate<T>, SuperMajorityCount<T>>,
    pub voters: BTreeSet<NodeId>,
}

impl<T> Default for VoteCount<T> {
    fn default() -> Self {
        Self {
            candidates: Default::default(),
            super_majorities: Default::default(),
            voters: Default::default(),
        }
    }
}

impl<T: Proposition> VoteCount<T> {
    pub fn count<V: Borrow<SignedVote<T>>>(
        votes: impl IntoIterator<Item = V>,
        faulty: &BTreeSet<NodeId>,
    ) -> Self {
        let mut count: VoteCount<T> = VoteCount::default();

        let mut votes_by_honest_voter: BTreeMap<NodeId, SignedVote<T>> = Default::default();

        for vote in votes.into_iter() {
            for unpacked_vote in vote.borrow().unpack_votes() {
                if faulty.contains(&unpacked_vote.voter) {
                    continue;
                }
                let existing_vote = votes_by_honest_voter
                    .entry(unpacked_vote.voter)
                    .or_insert_with(|| unpacked_vote.clone());
                if unpacked_vote.supersedes(existing_vote) {
                    *existing_vote = unpacked_vote.clone();
                }
            }
        }

        // We always include voters in the voter set (even if they are faulty)
        // so that we have an accurate reading of who has contributed votes.
        // This is done to to aid in split-vote detection
        count.voters.extend(votes_by_honest_voter.keys().copied());
        count.voters.extend(faulty.iter().copied());

        for vote in votes_by_honest_voter.into_values() {
            let candidate = vote.candidate();

            if let Ballot::SuperMajority { proposals, .. } = &vote.vote.ballot {
                let sm_count = count.super_majorities.entry(candidate.clone()).or_default();

                sm_count.count += 1;

                for (t, (id, sig)) in proposals {
                    sm_count
                        .proposals
                        .entry(t.clone())
                        .or_default()
                        .insert(*id as u64, sig.clone());
                }
            }

            let c = count.candidates.entry(candidate).or_default();
            *c += 1;
        }

        count
    }

    pub fn candidate_with_most_votes(&self) -> Option<(&Candidate<T>, usize)> {
        self.candidates
            .iter()
            .map(|(candidates, c)| (candidates, *c))
            .chain(
                self.super_majority_with_most_votes()
                    .map(|(candidates, sm_count)| (candidates, sm_count.count)),
            )
            .max_by_key(|(_, c)| *c)
    }

    pub fn super_majority_with_most_votes(
        &self,
    ) -> Option<(&Candidate<T>, &SuperMajorityCount<T>)> {
        self.super_majorities
            .iter()
            .max_by_key(|(_, sm_count)| sm_count.count)
    }

    pub fn is_split_vote(&self, voters: &PublicKeySet, n_voters: usize) -> bool {
        let most_votes = self
            .candidate_with_most_votes()
            .map(|(_, c)| c)
            .unwrap_or(0);

        let remaining_voters = n_voters - self.voters.len();

        // suppose the remaining votes go to the proposals with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        // We're in a split vote if even in the best case scenario where all
        // remaining votes are not enough to take us above the threshold.
        self.voters.len() > voters.threshold() && predicted_votes <= voters.threshold()
    }

    pub fn do_we_have_supermajority(&self, voters: &PublicKeySet) -> bool {
        let most_votes = self
            .candidate_with_most_votes()
            .map(|(_, c)| c)
            .unwrap_or_default();

        most_votes > voters.threshold()
    }

    pub fn get_decision(&self, voters: &PublicKeySet) -> Result<Option<BTreeMap<T, Signature>>> {
        if let Some((_candidate, sm_count)) = self.super_majority_with_most_votes() {
            if sm_count.count > voters.threshold() {
                let proposals = sm_count
                    .proposals
                    .iter()
                    .map(|(prop, sigs)| Ok((prop.clone(), voters.combine_signatures(sigs)?)))
                    .collect::<Result<_>>()?;
                return Ok(Some(proposals));
            }
        }

        Ok(None)
    }
}
