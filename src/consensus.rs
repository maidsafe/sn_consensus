use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use log::info;
use serde::Serialize;

use crate::sn_membership::Generation;
use crate::vote::{Ballot, Proposition, SignedVote, Vote, VoteCount};
use crate::{Error, Fault, NodeId, Result};

#[derive(Debug)]
pub struct Consensus<T: Proposition> {
    pub elders: PublicKeySet,
    pub n_elders: usize,
    pub secret_key: (NodeId, SecretKeyShare),
    pub seen_votes_cache: BTreeSet<SignatureShare>,
    pub votes: BTreeMap<NodeId, SignedVote<T>>,
    pub faults: BTreeMap<NodeId, Fault<T>>,
    pub decision: Option<Decision<T>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<T: Proposition> {
    pub votes: BTreeSet<SignedVote<T>>,
    pub proposals: BTreeMap<T, Signature>,
    pub faults: BTreeSet<Fault<T>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteResponse<T: Proposition> {
    WaitingForMoreVotes,
    Broadcast(SignedVote<T>),
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
            seen_votes_cache: Default::default(),
            votes: Default::default(),
            faults: Default::default(),
            decision: None,
        }
    }

    pub fn sign<M: Serialize>(&self, msg: &M) -> Result<SignatureShare> {
        Ok(self.secret_key.1.sign(&bincode::serialize(msg)?))
    }

    pub fn id(&self) -> NodeId {
        self.secret_key.0
    }

    pub fn faults(&self) -> BTreeSet<Fault<T>> {
        BTreeSet::from_iter(self.faults.values().cloned())
    }

    pub fn build_super_majority_vote(
        &self,
        votes: BTreeSet<SignedVote<T>>,
        faults: BTreeSet<Fault<T>>,
        gen: Generation,
    ) -> Result<SignedVote<T>> {
        let faulty = BTreeSet::from_iter(faults.iter().map(Fault::voter_at_fault));
        let proposals: BTreeMap<T, (NodeId, SignatureShare)> =
            crate::vote::proposals(&votes, &faulty)
                .into_iter()
                .map(|p| {
                    let sig = self.sign(&p)?;
                    Ok((p, (self.id(), sig)))
                })
                .collect::<Result<_>>()?;
        let ballot = Ballot::SuperMajority { votes, proposals }.simplify();
        let vote = Vote {
            gen,
            ballot,
            faults,
        };
        self.sign_vote(vote)
    }

    pub fn have_we_seen_this_vote_before(&self, signed_vote: &SignedVote<T>) -> bool {
        self.seen_votes_cache.contains(&signed_vote.sig)
    }

    // handover: gen = gen
    // membership: gen = pending_gen
    /// Handles a signed vote
    /// Returns the vote we cast and the reached consensus vote in case consensus was reached
    pub fn handle_signed_vote(&mut self, signed_vote: SignedVote<T>) -> Result<VoteResponse<T>> {
        info!("[{}] handling vote {:?}", self.id(), signed_vote);

        if self.decision.is_some() {
            info!("[{}] we've decided already, dropping vote", self.id());
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        if self.have_we_seen_this_vote_before(&signed_vote) {
            info!("[{}] dropping already processed vote", self.id());
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        if let Err(faults) = self.detect_byzantine_voters(&signed_vote) {
            info!("[{}] Found faults {:?}", self.id(), faults);
            self.faults.extend(faults);
        }

        if self.faults.contains_key(&signed_vote.voter) {
            info!("[{}] dropping vote from faulty voter", self.id());
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        if let Some(proposals) = self.get_decision(&signed_vote.vote_count())? {
            // This case is here to handle situations where this node has recieved
            // a faulty vote previously that is preventing it from accepting a network
            // decision using the sm_over_sm logic below.
            info!(
                "[{}] They terminated but we haven't yet, accepting decision",
                self.id()
            );
            let votes = crate::vote::simplify_votes(&self.votes.values().cloned().collect());
            let decision = Decision {
                votes,
                proposals,
                faults: signed_vote.vote.faults.clone(),
            };
            self.decision = Some(decision);
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        self.log_signed_vote(&signed_vote);

        let vote_count = VoteCount::count(
            self.votes.values(),
            &BTreeSet::from_iter(self.faults.keys().copied()),
        );

        if let Some(proposals) = self.get_decision(&vote_count)? {
            info!(
                "[{}] Detected super majority over super majorities: {proposals:?}",
                self.id()
            );
            let votes = crate::vote::simplify_votes(&self.votes.values().cloned().collect());
            let decision = Decision {
                votes,
                proposals,
                faults: self.faults(),
            };
            let vote = self.build_super_majority_vote(
                decision.votes.clone(),
                decision.faults.clone(),
                signed_vote.vote.gen,
            )?;
            self.decision = Some(decision);
            return Ok(VoteResponse::Broadcast(vote));
        }

        if self.is_split_vote(&vote_count) {
            info!("[{}] Detected split vote", self.id());
            let merge_vote = Vote {
                gen: signed_vote.vote.gen,
                ballot: Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
                faults: self.faults(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            let resp = if vote_count != signed_merge_vote.vote_count() {
                info!("[{}] broadcasting merge.", self.id());
                VoteResponse::Broadcast(self.cast_vote(signed_merge_vote)?)
            } else {
                info!("[{}] merge does not change counts, waiting.", self.id());
                VoteResponse::WaitingForMoreVotes
            };

            return Ok(resp);
        }

        if self.is_super_majority(&vote_count) {
            info!("[{}] Detected super majority", self.id());

            if let Some(our_vote) = self.votes.get(&self.id()) {
                // We voted during this generation.

                if our_vote.vote.is_super_majority_ballot() {
                    info!("[{}] We've already sent a super majority, waiting till we either have a split vote or SM / SM", self.id());
                    return Ok(VoteResponse::WaitingForMoreVotes);
                }
            }

            info!("[{}] broadcasting super majority", self.id());
            let signed_vote = self.build_super_majority_vote(
                self.votes.values().cloned().collect(),
                BTreeSet::from_iter(self.faults.values().cloned()),
                signed_vote.vote.gen,
            )?;

            return Ok(VoteResponse::Broadcast(self.cast_vote(signed_vote)?));
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.id()) {
            let signed_vote = self.sign_vote(Vote {
                gen: signed_vote.vote.gen,
                ballot: Ballot::Merge(BTreeSet::from_iter([signed_vote])),
                faults: self.faults(),
            })?;
            info!(
                "[{}] adopting ballot {:?}",
                self.id(),
                signed_vote.vote.ballot
            );

            Ok(VoteResponse::Broadcast(self.cast_vote(signed_vote)?))
        } else {
            info!("[{}] waiting for more votes", self.id());
            Ok(VoteResponse::WaitingForMoreVotes)
        }
    }

    pub fn sign_vote(&self, vote: Vote<T>) -> Result<SignedVote<T>> {
        Ok(SignedVote {
            voter: self.id(),
            sig: self.sign(&vote)?,
            vote,
        })
    }

    pub fn cast_vote(&mut self, signed_vote: SignedVote<T>) -> Result<SignedVote<T>> {
        info!("[{}] casting vote {:?}", self.id(), signed_vote);
        match self.handle_signed_vote(signed_vote.clone())? {
            VoteResponse::WaitingForMoreVotes => Ok(signed_vote),
            VoteResponse::Broadcast(vote) => Ok(vote),
        }
    }

    pub fn log_signed_vote(&mut self, signed_vote: &SignedVote<T>) {
        for vote in signed_vote.unpack_votes() {
            if self.seen_votes_cache.insert(vote.sig.clone()) {
                let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
                if vote.supersedes(existing_vote) {
                    *existing_vote = vote.clone()
                }
            }
        }
    }

    fn is_split_vote(&self, count: &VoteCount<T>) -> bool {
        let most_votes = count
            .candidate_with_most_votes()
            .map(|(_, c)| c)
            .unwrap_or(0);
        let remaining_voters = self.n_elders - count.voters.len();

        // suppose the remaining votes go to the proposals with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        count.voters.len() > self.elders.threshold() && predicted_votes <= self.elders.threshold()
    }

    pub fn is_super_majority(&self, count: &VoteCount<T>) -> bool {
        let most_votes = count
            .candidate_with_most_votes()
            .map(|(_, c)| c)
            .unwrap_or_default();

        most_votes > self.elders.threshold()
    }

    fn get_decision(&self, vote_count: &VoteCount<T>) -> Result<Option<BTreeMap<T, Signature>>> {
        if let Some((_candidate, sm_count)) = vote_count.super_majority_with_most_votes() {
            if sm_count.count > self.elders.threshold() {
                let proposals = sm_count
                    .proposals
                    .iter()
                    .map(|(prop, sigs)| Ok((prop.clone(), self.elders.combine_signatures(sigs)?)))
                    .collect::<Result<_>>()?;
                return Ok(Some(proposals));
            }
        }

        Ok(None)
    }

    pub fn detect_byzantine_voters(
        &self,
        signed_vote: &SignedVote<T>,
    ) -> std::result::Result<(), BTreeMap<NodeId, Fault<T>>> {
        let mut faults = BTreeMap::new();
        for vote in signed_vote.unpack_votes() {
            if self.have_we_seen_this_vote_before(vote) {
                continue;
            }

            if let Some(existing_vote) = self.votes.get(&vote.voter) {
                let fault = Fault::ChangedVote {
                    a: existing_vote.clone(),
                    b: vote.clone(),
                };

                if let Ok(()) = fault.validate(&self.elders) {
                    faults.insert(vote.voter, fault);
                }
            }

            {
                let fault = Fault::InvalidFault {
                    signed_vote: vote.clone(),
                };
                if let Ok(()) = fault.validate(&self.elders) {
                    faults.insert(vote.voter, fault);
                }
            }
        }

        if faults.is_empty() {
            Ok(())
        } else {
            Err(faults)
        }
    }

    /// Validates a vote recursively all the way down to the proposition (T)
    /// Assumes those propositions are correct, they MUST be checked beforehand by the caller
    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        signed_vote.validate_signature(&self.elders)?;
        if !self.have_we_seen_this_vote_before(signed_vote) {
            self.validate_vote(&signed_vote.vote)?
        }
        Ok(())
    }

    fn validate_vote(&self, vote: &Vote<T>) -> Result<()> {
        match &vote.ballot {
            Ballot::Propose(_) => Ok(()),
            Ballot::Merge(votes) => self.validate_child_vote(vote.gen, votes),
            Ballot::SuperMajority { votes, proposals } => {
                if !self.is_super_majority(&VoteCount::count(votes, &vote.known_faulty())) {
                    // TODO: this should be moved to fault detection
                    Err(Error::SuperMajorityBallotIsNotSuperMajority)
                } else if vote.proposals() != BTreeSet::from_iter(proposals.keys().cloned()) {
                    // TODO: this should be moved to fault detection
                    Err(Error::SuperMajorityProposalsDoesNotMatchVoteProposals)
                } else if proposals
                    .iter()
                    .try_for_each(|(p, (id, sig))| {
                        crate::verify_sig_share(&p, sig, *id, &self.elders)
                    })
                    .is_err()
                {
                    Err(Error::InvalidElderSignature)
                } else {
                    self.validate_child_vote(vote.gen, votes)
                }
            }
        }
    }

    fn validate_child_vote(&self, gen: Generation, votes: &BTreeSet<SignedVote<T>>) -> Result<()> {
        for child_vote in votes {
            // TODO: generation checking needs to move to sn_membership
            if child_vote.vote.gen != gen {
                return Err(Error::MergedVotesMustBeFromSameGen {
                    child_gen: child_vote.vote.gen,
                    merge_gen: gen,
                });
            }
            self.validate_signed_vote(child_vote)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blsttc::SecretKeySet;
    use rand::{prelude::StdRng, SeedableRng};

    #[test]
    fn test_have_we_seen_this_vote_before() {
        let mut rng = StdRng::from_seed([0u8; 32]);
        let elders_sk = SecretKeySet::random(10, &mut rng);
        let mut states = Vec::from_iter((1..=10).into_iter().map(|id| {
            Consensus::from(
                (id, elders_sk.secret_key_share(id as usize)),
                elders_sk.public_keys(),
                10,
            )
        }));

        for i in 0..10u8 {
            let vote = states[i as usize]
                .sign_vote(Vote {
                    gen: 0,
                    ballot: Ballot::Propose(i),
                    faults: Default::default(),
                })
                .unwrap();
            states[0].log_signed_vote(&vote);
        }

        // try existing vote
        let new_vote = states[2]
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(2u8),
                faults: Default::default(),
            })
            .unwrap();
        assert!(states[0].have_we_seen_this_vote_before(&new_vote));

        // try merge vote superseding existing vote
        let new_vote = states[0]
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Merge(BTreeSet::from_iter(
                    states[0].votes.iter().map(|(_, v)| v.clone()),
                )),
                faults: Default::default(),
            })
            .unwrap();
        assert!(!states[0].have_we_seen_this_vote_before(&new_vote));

        // try bad vote not superseding existing
        let new_vote = states[0]
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(44u8),
                faults: Default::default(),
            })
            .unwrap();
        assert!(!states[0].have_we_seen_this_vote_before(&new_vote));
    }
}
