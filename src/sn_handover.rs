use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeyShare, SecretKeyShare};
use core::fmt::Debug;
use log::info;
use rand::{CryptoRng, Rng};

use crate::consensus::{Consensus, VoteResponse};
use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::{Error, Result};

pub type UniqueSectionId = u64;

#[derive(Debug)]
pub struct Handover<T: Proposition> {
    pub consensus: Consensus<T>,
    pub gen: UniqueSectionId,
}

impl<T: Proposition> Handover<T> {
    pub fn from(secret_key: SecretKeyShare, elders: BTreeSet<PublicKeyShare>, gen: UniqueSectionId) -> Self {
        Handover::<T> {
            consensus: Consensus::<T>::from(secret_key, elders),
            gen,
        }
    }

    pub fn random(rng: impl Rng + CryptoRng, gen: UniqueSectionId) -> Self {
        Handover::<T> {
            consensus: Consensus::<T>::random(rng),
            gen,
        }
    }

    pub fn propose(&mut self, proposal: T) -> Result<SignedVote<T>> {
        let vote = Vote {
            gen: self.gen,
            ballot: Ballot::Propose(proposal),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_signed_vote(&signed_vote)?;
        Ok(self.cast_vote(signed_vote))
    }

    // Get someone up to speed on our view of the current votes
    pub fn anti_entropy(&self) -> Vec<SignedVote<T>> {
        info!(
            "[HDVR] anti-entropy from {:?}",
            self.public_key_share()
        );

        self.consensus.votes.values().cloned().collect()
    }

    fn resolve_votes(&self, votes: &BTreeSet<SignedVote<T>>) -> Option<T> {
        let (winning_proposals, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .unwrap_or_default();

        // we need to choose one deterministically
        // proposals are comparable because they impl Ord so we arbitrarily pick the max
        winning_proposals.into_iter().max()
    }

    pub fn public_key_share(&self) -> PublicKeyShare {
        self.consensus.public_key_share()
    }

    pub fn handle_signed_vote(
        &mut self,
        signed_vote: SignedVote<T>,
    ) -> Result<Option<SignedVote<T>>> {
        self.validate_signed_vote(&signed_vote)?;

        let vote_response = self
            .consensus
            .handle_signed_vote(signed_vote, self.gen)?;

        match vote_response {
            VoteResponse::Broadcast(vote) => {
                Ok(Some(vote))
            }
            VoteResponse::Decided(_vote) => {
                Ok(None)
            }
            VoteResponse::WaitingForMoreVotes => Ok(None),
        }
    }

    pub fn sign_vote(&self, vote: Vote<T>) -> Result<SignedVote<T>> {
        self.consensus.sign_vote(vote)
    }

    pub fn cast_vote(&mut self, signed_vote: SignedVote<T>) -> SignedVote<T> {
        self.log_signed_vote(&signed_vote);
        signed_vote
    }

    fn log_signed_vote(&mut self, signed_vote: &SignedVote<T>) {
        self.consensus.log_signed_vote(signed_vote);
    }

    pub fn count_votes(
        &self,
        votes: &BTreeSet<SignedVote<T>>,
    ) -> BTreeMap<BTreeSet<T>, usize> {
        self.consensus.count_votes(votes)
    }

    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        signed_vote.validate_signature()?;
        self.validate_vote(&signed_vote.vote)?;
        self.consensus.validate_is_elder(signed_vote.voter)?;
        self.consensus
            .validate_vote_supersedes_existing_vote(signed_vote)?;
        self.consensus
            .validate_voters_have_not_changed_proposals(signed_vote)?;
        Ok(())
    }

    fn validate_vote(&self, vote: &Vote<T>) -> Result<()> {
        if vote.gen != self.gen {
            return Err(Error::VoteWithInvalidUniqueSectionId {
                vote_gen: vote.gen,
                gen: self.gen,
            });
        }

        match &vote.ballot {
            Ballot::Propose(proposal) => self.validate_proposal(proposal.clone()),
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
                if !self.consensus.is_super_majority(
                    &votes
                        .iter()
                        .flat_map(SignedVote::unpack_votes)
                        .cloned()
                        .collect(),
                )? {
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

    // Placeholder for now, may be useful for sn_node
    pub fn validate_proposal(&self, _proposal: T) -> Result<()> {
        Ok(())
    }
}
