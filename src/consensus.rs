use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, SecretKeyShare, SignatureShare};
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
    Decided(SignedVote<T>),
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

    // handover: gen = gen
    // membership: gen = pending_gen
    /// Handles a signed vote
    /// Returns the vote we cast and the reached consensus vote in case consensus was reached
    pub fn handle_signed_vote(
        &mut self,
        signed_vote: SignedVote<T>,
        gen: Generation,
    ) -> Result<VoteResponse<T>> {
        self.log_signed_vote(&signed_vote);

        if self.is_split_vote(&self.votes.values().cloned().collect()) {
            info!("[MBR] Detected split vote");
            let merge_vote = Vote {
                gen,
                ballot: Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            if let Some(our_vote) = self.votes.get(&self.id()) {
                let proposals_we_voted_for =
                    BTreeSet::from_iter(our_vote.proposals().into_iter().map(|(_, r)| r));
                let proposals_we_would_vote_for: BTreeSet<_> = signed_merge_vote
                    .proposals()
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect();

                if proposals_we_voted_for == proposals_we_would_vote_for {
                    info!("[MBR] This vote didn't add new information, waiting for more votes...");
                    return Ok(VoteResponse::WaitingForMoreVotes);
                }
            }

            info!("[MBR] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return Ok(VoteResponse::Broadcast(self.cast_vote(signed_merge_vote)));
        }

        if self.is_super_majority_over_super_majorities(&self.votes.values().cloned().collect()) {
            info!("[MBR] Detected super majority over super majorities");
            // store a proof of what the network decided in our history so that we can onboard future procs.
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();

            let vote = Vote { gen, ballot };
            let signed_vote = self.sign_vote(vote)?;

            // return obtained super majority over super majority (aka consensus)
            return Ok(VoteResponse::Decided(signed_vote));
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
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();
            let vote = Vote { gen, ballot };
            let signed_vote = self.sign_vote(vote)?;
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
            let proposals = BTreeSet::from_iter(vote.proposals().into_iter().map(|(_, prop)| prop));
            let c = count.entry(proposals).or_default();
            *c += 1;
        }

        count
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

    fn is_super_majority_over_super_majorities(&self, votes: &BTreeSet<SignedVote<T>>) -> bool {
        let count_of_agreeing_super_majorities = self
            .count_votes(&BTreeSet::from_iter(
                votes
                    .iter()
                    .filter(|v| v.vote.is_super_majority_ballot())
                    .cloned(),
            ))
            .into_iter()
            .map(|(_, count)| count)
            .max()
            .unwrap_or(0);

        count_of_agreeing_super_majorities > self.elders.threshold()
    }

    /// Validates a vote recursively all the way down to the proposition (T)
    /// Assumes those propositions are correct, they MUST be checked beforehand by the caller
    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        self.verify_sig_share(&signed_vote.vote, signed_vote.voter, &signed_vote.sig)?;
        self.validate_vote(&signed_vote.vote)?;
        self.validate_vote_supersedes_existing_vote(signed_vote)?;
        self.validate_voters_have_not_changed_proposals(signed_vote)?;
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
            Ballot::SuperMajority(votes) => {
                if !self.is_super_majority(
                    &votes
                        .iter()
                        .flat_map(SignedVote::unpack_votes)
                        .cloned()
                        .collect(),
                ) {
                    Err(Error::SuperMajorityBallotIsNotSuperMajority)
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

    fn validate_voters_have_not_changed_proposals(
        &self,
        signed_vote: &SignedVote<T>,
    ) -> Result<()> {
        // Ensure that nobody is trying to change their Proposal proposals.
        let proposals: BTreeSet<(NodeId, T)> = self
            .votes
            .values()
            .flat_map(|v| v.proposals())
            .chain(signed_vote.proposals())
            .collect();

        let voters = BTreeSet::from_iter(proposals.iter().map(|(actor, _)| actor));
        if voters.len() != proposals.len() {
            Err(Error::VoterChangedVote)
        } else {
            Ok(())
        }
    }
}
