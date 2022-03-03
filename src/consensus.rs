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
        if let Some(previous_vote_from_voter) = self.votes.get(&signed_vote.voter) {
            previous_vote_from_voter.supersedes(signed_vote)
        } else {
            // if we have no votes from this voter, then it is new
            false
        }
    }

    // handover: gen = gen
    // membership: gen = pending_gen
    /// Handles a signed vote
    /// Returns the vote we cast and the reached consensus vote in case consensus was reached
    pub fn handle_signed_vote(&mut self, signed_vote: SignedVote<T>) -> Result<VoteResponse<T>> {
        info!("[MBR-{}] handling vote {:?}", self.id(), signed_vote);

        if self.have_we_seen_this_vote_before(&signed_vote) {
            info!("[MBR-{}] skipping already processed vote", self.id());
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        if let Err(faults) = self.detect_byzantine_voters(&signed_vote) {
            info!("[MBR-{}] Found faults {:?}", self.id(), faults);
            self.faults.extend(faults);
        }

        if self.faults.contains_key(&signed_vote.voter) {
            info!("[MBR-{}] dropping vote from faulty voter", self.id());
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        let their_decision = self.get_decision(&signed_vote.vote_count())?;

        if let Some(decision) = self.decision.clone() {
            let resp = if their_decision.is_none() {
                info!(
                    "[MBR-{}] We've already terminated, responding with decision",
                    self.id()
                );
                let vote = self.build_super_majority_vote(
                    decision.votes,
                    decision.faults,
                    signed_vote.vote.gen,
                )?;
                VoteResponse::Broadcast(vote)
            } else {
                info!("[MBR-{}] We've both terminated, no-op", self.id());
                VoteResponse::WaitingForMoreVotes
            };

            return Ok(resp);
        }

        self.log_signed_vote(&signed_vote);

        if let Some(proposals) = their_decision {
            // This case is here to handle situations where this node has recieved
            // a faulty vote previously that is preventing it from accepting a network
            // decision using the sm_over_sm logic below.
            info!(
                "[MBR-{}] They terminated but we haven't yet, accepting decision",
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

        let vote_count = VoteCount::count(
            self.votes.values(),
            &BTreeSet::from_iter(self.faults.keys().copied()),
        );

        if let Some(proposals) = self.get_decision(&vote_count)? {
            info!(
                "[MBR-{}] Detected super majority over super majorities: {proposals:?}",
                self.id()
            );
            let votes = crate::vote::simplify_votes(&self.votes.values().cloned().collect());
            let decision = Decision {
                votes,
                proposals,
                faults: self.faults(),
            };
            self.decision = Some(decision);
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        if self.is_split_vote(&vote_count) {
            info!("[MBR-{}] Detected split vote", self.id());
            let merge_vote = Vote {
                gen: signed_vote.vote.gen,
                ballot: Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
                faults: self.faults(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            let resp = if vote_count != signed_merge_vote.vote_count() {
                info!("[MBR-{}] broadcasting merge.", self.id());
                VoteResponse::Broadcast(self.cast_vote(signed_merge_vote)?)
            } else {
                info!("[MBR-{}] merge does not change counts, waiting.", self.id());
                VoteResponse::WaitingForMoreVotes
            };

            return Ok(resp);
        }

        if self.is_super_majority(&vote_count) {
            info!("[MBR-{}] Detected super majority", self.id());

            if let Some(our_vote) = self.votes.get(&self.id()) {
                // We voted during this generation.

                if our_vote.vote.is_super_majority_ballot() {
                    info!("[MBR-{}] We've already sent a super majority, waiting till we either have a split vote or SM / SM", self.id());
                    return Ok(VoteResponse::WaitingForMoreVotes);
                }
            }

            info!("[MBR-{}] broadcasting super majority", self.id());
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
                "[MBR-{}] adopting ballot {:?}",
                self.id(),
                signed_vote.vote.ballot
            );

            Ok(VoteResponse::Broadcast(self.cast_vote(signed_vote)?))
        } else {
            info!("[MBR-{}] waiting for more votes", self.id());
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
            let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
            if vote.supersedes(existing_vote) {
                *existing_vote = vote.clone()
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
        if let Some((_candidate, shares_by_voter)) = vote_count.super_majority_with_most_votes() {
            if shares_by_voter.len() > self.elders.threshold() {
                let mut proposal_sigs: BTreeMap<T, BTreeSet<(u64, SignatureShare)>> =
                    Default::default();

                for (id, shares) in shares_by_voter {
                    shares.iter().for_each(|(prop, sig)| {
                        proposal_sigs
                            .entry(prop.clone())
                            .or_default()
                            .insert((*id as u64, sig.clone()));
                    });
                }
                let proposals = proposal_sigs
                    .into_iter()
                    .map(|(prop, sigs)| Ok((prop, self.elders.combine_signatures(sigs)?)))
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
        if let Some(existing_vote) = self.votes.get(&signed_vote.voter) {
            let fault = Fault::ChangedVote {
                a: existing_vote.clone(),
                b: signed_vote.clone(),
            };

            if let Ok(()) = fault.validate(&self.elders) {
                faults.insert(signed_vote.voter, fault);
            }
        }

        {
            let fault = Fault::InvalidFault {
                signed_vote: signed_vote.clone(),
            };
            if let Ok(()) = fault.validate(&self.elders) {
                faults.insert(signed_vote.voter, fault);
            }
        }

        // TODO: recursively check for faulty votes

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
        self.validate_vote(&signed_vote.vote)?;
        Ok(())
    }

    fn validate_vote(&self, vote: &Vote<T>) -> Result<()> {
        match &vote.ballot {
            Ballot::Propose(_) => Ok(()),
            Ballot::Merge(votes) => {
                // TODO: generation checking needs to move to sn_membership
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
                    for child_vote in votes.iter() {
                        // TODO: generation checking needs to move to sn_membership
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

        states[0].votes = BTreeMap::from_iter((0..10u8).map(|i| {
            (
                i + 1,
                states[i as usize]
                    .sign_vote(Vote {
                        gen: 0,
                        ballot: Ballot::Propose(i),
                        faults: Default::default(),
                    })
                    .unwrap(),
            )
        }));

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
