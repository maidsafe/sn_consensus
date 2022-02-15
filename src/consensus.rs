use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use log::info;
use serde::Serialize;

use crate::sn_membership::Generation;
use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::{Error, NodeId, Result};

#[derive(Debug)]
pub struct Consensus<T: Proposition> {
    pub elders: PublicKeySet,
    pub n_elders: usize,
    pub secret_key: (NodeId, SecretKeyShare),
    pub votes: BTreeMap<NodeId, SignedVote<T>>,
}

pub enum VoteResponse<T: Proposition> {
    WaitingForMoreVotes,
    Broadcast(SignedVote<T>),
    Decided {
        votes: BTreeSet<SignedVote<T>>,
        proposals: BTreeMap<T, Signature>,
    },
}

impl<T: Proposition> Consensus<T> {
    pub fn from(
        secret_key: (NodeId, SecretKeyShare),
        elders: PublicKeySet,
        n_elders: usize,
    ) -> Self {
        Consensus::<T> {
            elders,
            n_elders,
            secret_key,
            votes: Default::default(),
        }
    }

    pub fn verify_sig_share<M: Serialize>(
        &self,
        msg: &M,
        elder: NodeId,
        sig: &SignatureShare,
    ) -> Result<()> {
        let public_key = self.elders.public_key_share(elder as u64);
        let msg_bytes = bincode::serialize(msg)?;
        if public_key.verify(sig, msg_bytes) {
            Ok(())
        } else {
            Err(Error::InvalidElderSignature)
        }
    }

    pub fn sign<M: Serialize>(&self, msg: &M) -> Result<SignatureShare> {
        Ok(self.secret_key.1.sign(&bincode::serialize(msg)?))
    }

    pub fn id(&self) -> NodeId {
        self.secret_key.0
    }

    pub fn build_super_majority_vote(
        &self,
        votes: BTreeSet<SignedVote<T>>,
        gen: Generation,
    ) -> Result<SignedVote<T>> {
        let proposals: BTreeMap<T, (NodeId, SignatureShare)> = self
            .proposals(&votes)
            .into_iter()
            .map(|p| {
                let sig = self.sign(&p)?;
                Ok((p, (self.secret_key.0, sig)))
            })
            .collect::<Result<_>>()?;
        let ballot = Ballot::SuperMajority { votes, proposals }.simplify();
        let vote = Vote { gen, ballot };
        self.sign_vote(vote)
    }

    pub fn is_new_vote_from_voter(&self, signed_vote: &SignedVote<T>) -> bool {
        if let Some(previous_vote_from_voter) = self.votes.get(&signed_vote.voter) {
            if signed_vote == previous_vote_from_voter {
                false
            } else {
                signed_vote.supersedes(previous_vote_from_voter)
            }
        } else {
            // if we have no votes from this voter, then it is new
            true
        }
    }

    // handover: gen = gen
    // membership: gen = pending_gen
    /// Handles a signed vote
    /// Returns the vote we cast and the reached consensus vote in case consensus was reached
    pub fn handle_signed_vote(
        &mut self,
        signed_vote: SignedVote<T>,
        gen: Generation,
    ) -> Result<VoteResponse<T>> {
        let they_terminated = self
            .get_super_majority_over_super_majorities(
                &signed_vote
                    .unpack_votes()
                    .into_iter()
                    .map(|v| v.to_owned())
                    .collect(),
            )?
            .is_some();
        let we_terminated = self
            .get_super_majority_over_super_majorities(&self.votes.values().cloned().collect())?
            .is_some();

        if we_terminated && !they_terminated && self.is_new_vote_from_voter(&signed_vote) {
            info!("[MBR] Obtained new vote from {} after having already reached termination, sending out broadcast for others to catch up.", signed_vote.voter);
            let proof_sm_over_sm =
                self.build_super_majority_vote(self.votes.values().cloned().collect(), gen)?;
            assert!(self
                .get_super_majority_over_super_majorities(
                    &proof_sm_over_sm
                        .unpack_votes()
                        .into_iter()
                        .map(|v| v.to_owned())
                        .collect()
                )?
                .is_some());
            return Ok(VoteResponse::Broadcast(proof_sm_over_sm));
        }

        // don't log new votes anymore if we terminated
        if !we_terminated {
            self.log_signed_vote(&signed_vote);
        }

        if self.is_split_vote(&self.votes.values().cloned().collect()) {
            info!("[MBR] Detected split vote");
            let merge_vote = Vote {
                gen,
                ballot: Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            if let Some(our_vote) = self.votes.get(&self.id()) {
                let proposals_we_voted_for = our_vote.proposals();
                let proposals_we_would_vote_for = signed_merge_vote.proposals();

                if proposals_we_voted_for == proposals_we_would_vote_for {
                    info!("[MBR] This vote didn't add new information, waiting for more votes...");
                    return Ok(VoteResponse::WaitingForMoreVotes);
                }
            }

            info!("[MBR] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return Ok(VoteResponse::Broadcast(self.cast_vote(signed_merge_vote)));
        }

        if let Some(proposals) =
            self.get_super_majority_over_super_majorities(&self.votes.values().cloned().collect())?
        {
            info!("[MBR] Detected super majority over super majorities: {proposals:?}");
            return Ok(VoteResponse::Decided {
                votes: self.votes.values().cloned().collect(),
                proposals,
            });
        }

        if self.is_super_majority(&self.votes.values().cloned().collect()) {
            info!("[MBR] Detected super majority");

            if let Some(our_vote) = self.votes.get(&self.id()) {
                // We voted during this generation.

                if our_vote.vote.is_super_majority_ballot() {
                    info!("[MBR] We've already sent a super majority, waiting till we either have a split vote or SM / SM");
                    return Ok(VoteResponse::WaitingForMoreVotes);
                }
            }

            info!("[MBR] broadcasting super majority");
            let signed_vote =
                self.build_super_majority_vote(self.votes.values().cloned().collect(), gen)?;
            return Ok(VoteResponse::Broadcast(self.cast_vote(signed_vote)));
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.id()) {
            let signed_vote = self.sign_vote(Vote {
                gen,
                ballot: signed_vote.vote.ballot,
            })?;
            return Ok(VoteResponse::Broadcast(self.cast_vote(signed_vote)));
        }

        Ok(VoteResponse::WaitingForMoreVotes)
    }

    pub fn sign_vote(&self, vote: Vote<T>) -> Result<SignedVote<T>> {
        Ok(SignedVote {
            voter: self.secret_key.0,
            sig: self.sign(&vote)?,
            vote,
        })
    }

    pub fn cast_vote(&mut self, signed_vote: SignedVote<T>) -> SignedVote<T> {
        self.log_signed_vote(&signed_vote);
        signed_vote
    }

    pub fn log_signed_vote(&mut self, signed_vote: &SignedVote<T>) {
        for vote in signed_vote.unpack_votes() {
            let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
            if vote.supersedes(existing_vote) {
                *existing_vote = vote.clone()
            }
        }
    }

    pub fn count_votes(&self, votes: &BTreeSet<SignedVote<T>>) -> BTreeMap<BTreeSet<T>, usize> {
        let mut count: BTreeMap<BTreeSet<T>, usize> = Default::default();

        for vote in votes.iter() {
            let proposals = vote.proposals();
            let c = count.entry(proposals).or_default();
            *c += 1;
        }

        count
    }

    fn proposals(&self, votes: &BTreeSet<SignedVote<T>>) -> BTreeSet<T> {
        BTreeSet::from_iter(votes.iter().flat_map(|v| v.proposals()))
    }

    fn is_split_vote(&self, votes: &BTreeSet<SignedVote<T>>) -> bool {
        let counts = self.count_votes(votes);
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let voters = BTreeSet::from_iter(votes.iter().map(|v| v.voter));
        let remaining_voters = self.n_elders - voters.len();

        // give the remaining votes to the proposals with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        voters.len() > self.elders.threshold() && predicted_votes <= self.elders.threshold()
    }

    pub fn is_super_majority(&self, votes: &BTreeSet<SignedVote<T>>) -> bool {
        // TODO: super majority should always just be the largest 7 members
        let most_votes = self
            .count_votes(votes)
            .values()
            .max()
            .cloned()
            .unwrap_or_default();

        most_votes > self.elders.threshold()
    }

    fn get_super_majority_over_super_majorities(
        &self,
        votes: &BTreeSet<SignedVote<T>>,
    ) -> Result<Option<BTreeMap<T, Signature>>> {
        let sm_votes = BTreeSet::from_iter(
            votes
                .iter()
                .filter(|v| v.vote.is_super_majority_ballot())
                .cloned(),
        );
        if let Some((props, count_of_sm)) = self
            .count_votes(&sm_votes)
            .into_iter()
            .max_by_key(|(_, c)| *c)
        {
            if count_of_sm > self.elders.threshold() {
                let mut proposal_sigs: BTreeMap<T, BTreeSet<(u64, SignatureShare)>> =
                    Default::default();
                let proposals_from_each_supermajority = sm_votes
                    .iter()
                    .filter(|sm| sm.proposals() == props)
                    .flat_map(|v| match &v.vote.ballot {
                        Ballot::SuperMajority { proposals, .. } => proposals.clone(),
                        _ => Default::default(),
                    });
                for (prop, (id, sig)) in proposals_from_each_supermajority {
                    proposal_sigs
                        .entry(prop)
                        .or_default()
                        .insert((id as u64, sig));
                }

                return Ok(Some(
                    proposal_sigs
                        .into_iter()
                        .map(|(prop, sigs)| Ok((prop, self.elders.combine_signatures(sigs)?)))
                        .collect::<Result<_>>()?,
                ));
            }
        }

        Ok(None)
    }

    /// Validates a vote recursively all the way down to the proposition (T)
    /// Assumes those propositions are correct, they MUST be checked beforehand by the caller
    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        self.verify_sig_share(&signed_vote.vote, signed_vote.voter, &signed_vote.sig)?;
        self.validate_vote(&signed_vote.vote)?;
        self.validate_vote_supersedes_existing_vote(signed_vote)?;
        Ok(())
    }

    fn validate_vote(&self, vote: &Vote<T>) -> Result<()> {
        match &vote.ballot {
            Ballot::Propose(_) => Ok(()),
            Ballot::Merge(votes) => {
                for child_vote in votes.iter() {
                    if child_vote.vote.gen != vote.gen {
                        return Err(Error::MergedVotesMustBeFromSameGen {
                            child_gen: child_vote.vote.gen,
                            merge_gen: vote.gen,
                        });
                    }
                    self.validate_signed_vote(child_vote)?;
                }
                Ok(())
            }
            Ballot::SuperMajority { votes, proposals } => {
                if !self.is_super_majority(
                    &votes
                        .iter()
                        .flat_map(SignedVote::unpack_votes)
                        .cloned()
                        .collect(),
                ) {
                    Err(Error::SuperMajorityBallotIsNotSuperMajority)
                } else if vote.proposals() != BTreeSet::from_iter(proposals.keys().cloned()) {
                    Err(Error::SuperMajorityProposalsDoesNotMatchVoteProposals)
                } else if proposals
                    .iter()
                    .try_for_each(|(p, (id, sig))| self.verify_sig_share(&p, *id, sig))
                    .is_err()
                {
                    Err(Error::InvalidElderSignature)
                } else {
                    for child_vote in votes.iter() {
                        if child_vote.vote.gen != vote.gen {
                            return Err(Error::MergedVotesMustBeFromSameGen {
                                child_gen: child_vote.vote.gen,
                                merge_gen: vote.gen,
                            });
                        }
                        self.validate_signed_vote(child_vote)?;
                    }
                    Ok(())
                }
            }
        }
    }

    fn validate_vote_supersedes_existing_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        if self.votes.contains_key(&signed_vote.voter)
            && !signed_vote.supersedes(&self.votes[&signed_vote.voter])
            && !self.votes[&signed_vote.voter].supersedes(signed_vote)
        {
            Err(Error::ExistingVoteIncompatibleWithNewVote)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blsttc::SecretKeySet;
    use rand::{prelude::StdRng, SeedableRng};

    #[test]
    fn test_is_new_vote_from_voter() {
        let mut rng = StdRng::from_seed([0u8; 32]);
        let elders_sk = SecretKeySet::random(10, &mut rng);
        let mut consensus = Consensus::from(
            (1u8, elders_sk.secret_key_share(1usize)),
            elders_sk.public_keys(),
            10,
        );

        consensus.votes = BTreeMap::from_iter((0..10u8).map(|i| {
            (
                i,
                consensus
                    .sign_vote(Vote {
                        gen: 0,
                        ballot: Ballot::Propose(i),
                    })
                    .unwrap(),
            )
        }));

        // try existing vote
        let new_vote = consensus
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(2u8),
            })
            .unwrap();
        // println!("new_vote: {:#?}", new_vote);
        // println!("our_vote: {:#?}", consensus.votes);
        assert!(!consensus.is_new_vote_from_voter(&new_vote));

        // try merge vote superseding existing vote
        let new_vote = consensus
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Merge(BTreeSet::from_iter(
                    consensus.votes.iter().map(|(_, v)| v.clone()),
                )),
            })
            .unwrap();
        // println!("new_vote: {:#?}", new_vote);
        // println!("our_vote: {:#?}", consensus.votes);
        assert!(consensus.is_new_vote_from_voter(&new_vote));

        // try bad vote not superseding existing
        let new_vote = consensus
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(44u8),
            })
            .unwrap();
        // println!("new_vote: {:#?}", new_vote);
        // println!("our_vote: {:#?}", consensus.votes);
        assert!(!consensus.is_new_vote_from_voter(&new_vote));
    }
}
