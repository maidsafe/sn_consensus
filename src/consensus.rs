use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, SecretKeyShare, SignatureShare};
use log::info;
use serde::Serialize;

use crate::sn_membership::Generation;
use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::{Decision, Fault, NodeId, Result, VoteCount};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consensus<T: Proposition> {
    pub elders: PublicKeySet,
    pub n_elders: usize,
    pub secret_key: (NodeId, SecretKeyShare),
    pub processed_votes_cache: BTreeSet<SignatureShare>,
    pub votes: BTreeMap<NodeId, SignedVote<T>>,
    pub faults: BTreeMap<NodeId, Fault<T>>,
    pub decision: Option<Decision<T>>,
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
            processed_votes_cache: Default::default(),
            votes: Default::default(),
            faults: Default::default(),
            decision: None,
        }
    }

    pub fn sign<M: Serialize>(&self, msg: &M) -> Result<SignatureShare> {
        Ok(self.secret_key.1.sign(bincode::serialize(msg)?))
    }

    pub fn id(&self) -> NodeId {
        self.secret_key.0
    }

    pub fn faults(&self) -> BTreeSet<Fault<T>> {
        BTreeSet::from_iter(self.faults.values().cloned())
    }

    pub fn faulty_ids(&self) -> BTreeSet<NodeId> {
        BTreeSet::from_iter(self.faults.keys().copied())
    }

    pub fn build_super_majority_vote(
        &self,
        votes: BTreeSet<SignedVote<T>>,
        faults: BTreeSet<Fault<T>>,
        gen: Generation,
    ) -> Result<SignedVote<T>> {
        let faulty = BTreeSet::from_iter(faults.iter().map(Fault::voter_at_fault));

        let proposals = VoteCount::count(&votes, &faulty)
            .candidate_with_most_votes()
            .map(|(candidate, _)| candidate.proposals.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|proposal| {
                let sig = self.sign(&proposal)?;
                Ok((proposal, (self.id(), sig)))
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

        if self.have_we_processed_vote(&signed_vote) {
            info!("[{}] dropping already processed vote", self.id());
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        signed_vote.validate(&self.elders, &self.processed_votes_cache)?;

        if let Err(faults) = signed_vote.detect_byzantine_faults(
            &self.elders,
            &self.votes,
            &self.processed_votes_cache,
        ) {
            info!("[{}] Found faults {:?}", self.id(), faults);
            self.faults.extend(faults);
        }

        if self.faults.contains_key(&signed_vote.voter) {
            info!("[{}] dropping vote from faulty voter", self.id());
            return Ok(VoteResponse::WaitingForMoreVotes);
        }

        self.process_signed_vote(signed_vote)
    }

    fn process_signed_vote(&mut self, signed_vote: SignedVote<T>) -> Result<VoteResponse<T>> {
        self.log_processed_signed_vote(&signed_vote);

        if let Some(proposals) = signed_vote.vote_count().get_decision(&self.elders)? {
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

        let vote_count = VoteCount::count(self.votes.values(), &self.faulty_ids());

        if let Some(proposals) = vote_count.get_decision(&self.elders)? {
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

        if vote_count.is_split_vote(&self.elders, self.n_elders) {
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

        if vote_count.do_we_have_supermajority(&self.elders) {
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

    fn have_we_processed_vote(&self, signed_vote: &SignedVote<T>) -> bool {
        self.processed_votes_cache.contains(&signed_vote.sig)
    }

    fn log_processed_signed_vote(&mut self, signed_vote: &SignedVote<T>) {
        for vote in signed_vote.unpack_votes() {
            if self.processed_votes_cache.insert(vote.sig.clone()) {
                let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
                if vote.supersedes(existing_vote) {
                    *existing_vote = vote.clone()
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

        for i in 0..10u8 {
            let vote = states[i as usize]
                .sign_vote(Vote {
                    gen: 0,
                    ballot: Ballot::Propose(i),
                    faults: Default::default(),
                })
                .unwrap();
            states[0].log_processed_signed_vote(&vote);
        }

        // try existing vote
        let new_vote = states[2]
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(2u8),
                faults: Default::default(),
            })
            .unwrap();
        assert!(states[0].have_we_processed_vote(&new_vote));

        // try merge vote superseding existing vote
        let new_vote = states[0]
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Merge(BTreeSet::from_iter(states[0].votes.values().cloned())),
                faults: Default::default(),
            })
            .unwrap();
        assert!(!states[0].have_we_processed_vote(&new_vote));

        // try bad vote not superseding existing
        let new_vote = states[0]
            .sign_vote(Vote {
                gen: 0,
                ballot: Ballot::Propose(44u8),
                faults: Default::default(),
            })
            .unwrap();
        assert!(!states[0].have_we_processed_vote(&new_vote));
    }
}
