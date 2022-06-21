use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
};

use blsttc::{Fr, PublicKeySet, Signature, SignatureShare};

use crate::{Ballot, Fault, NodeId, Proposition, Result, SignedVote};

/// A Candidate is a potential outcome of consensus run.
#[derive(Debug, Clone)]
pub struct Candidate<T: Proposition> {
    /// The set of proposals that won the vote
    pub proposals: BTreeSet<T>,
    /// Faults that were detected in this consensus run.
    pub faults: BTreeSet<Fault<T>>,
}

impl<T: Proposition> PartialEq for Candidate<T> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_repr() == other.cmp_repr()
    }
}

impl<T: Proposition> Eq for Candidate<T> {}

impl<T: Proposition> PartialOrd for Candidate<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Proposition> Ord for Candidate<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cmp_repr().cmp(&other.cmp_repr())
    }
}

impl<T: Proposition> Default for Candidate<T> {
    fn default() -> Self {
        Self {
            proposals: Default::default(),
            faults: Default::default(),
        }
    }
}

impl<T: Proposition> Candidate<T> {
    pub fn faulty_ids(&self) -> BTreeSet<NodeId> {
        self.faults.iter().map(|f| f.voter_at_fault()).collect()
    }

    fn cmp_repr(&self) -> (&BTreeSet<T>, BTreeSet<NodeId>) {
        (&self.proposals, self.faulty_ids())
    }
}

/// The count of voters voting for the same Candidate with a super-majority ballot
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SuperMajorityCount {
    pub count: usize,
    /// Super-majority ballots come with a signature share signing over the winning proposals
    pub proposals_sig_shares: BTreeMap<Fr, SignatureShare>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteCount<T: Proposition> {
    pub candidates: BTreeMap<Candidate<T>, usize>,
    pub super_majorities: BTreeMap<Candidate<T>, SuperMajorityCount>,
    pub voters: BTreeSet<NodeId>,
}

impl<T: Proposition> Default for VoteCount<T> {
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

            if let Ballot::SuperMajority {
                proposals_sig_share,
                ..
            } = vote.vote.ballot
            {
                let sm_count = count.super_majorities.entry(candidate.clone()).or_default();

                sm_count.count += 1;
                sm_count
                    .proposals_sig_shares
                    .insert(Fr::from(vote.voter as u64), proposals_sig_share);
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

    pub fn super_majority_with_most_votes(&self) -> Option<(&Candidate<T>, &SuperMajorityCount)> {
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

    pub fn signed_decision(
        &self,
        voters: &PublicKeySet,
    ) -> Result<Option<(&BTreeSet<T>, Signature)>> {
        if let Some((candidate, sm_count)) = self.super_majority_with_most_votes() {
            if sm_count.count > voters.threshold() {
                let proposals_sig = voters.combine_signatures(&sm_count.proposals_sig_shares)?;
                return Ok(Some((&candidate.proposals, proposals_sig)));
            }
        }

        Ok(None)
    }
}
