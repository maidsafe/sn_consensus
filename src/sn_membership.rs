use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, SecretKeyShare, Signature};
use core::fmt::Debug;
use log::info;
use serde::{Deserialize, Serialize};

use crate::consensus::{Consensus, VoteResponse};
use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::{Error, Fault, NodeId, Result};

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;

#[derive(Debug)]
pub struct HistoryEntry<T: Proposition> {
    pub votes: BTreeSet<SignedVote<Reconfig<T>>>,
    pub proposals: BTreeMap<Reconfig<T>, Signature>,
    pub faults: BTreeSet<Fault<Reconfig<T>>>,
}

#[derive(Debug)]
pub struct Membership<T: Proposition> {
    pub consensus: Consensus<Reconfig<T>>,
    // TODO: we need faulty elder detection
    // pub faulty_elders: BTreeMap<PublicKeyShare, BTreeSet<SignedVote<Reconfig<T>>>>,
    pub gen: Generation,
    pub pending_gen: Generation,
    pub forced_reconfigs: BTreeMap<Generation, BTreeSet<Reconfig<T>>>, // TODO: change to bootstrap members
    pub history: BTreeMap<Generation, HistoryEntry<T>>, // for onboarding new procs, the vote proving super majority
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Reconfig<T: Proposition> {
    Join(T),
    Leave(T),
}

impl<T: Proposition> Debug for Reconfig<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reconfig::Join(a) => write!(f, "J{:?}", a),
            Reconfig::Leave(a) => write!(f, "L{:?}", a),
        }
    }
}

impl<T: Proposition> Reconfig<T> {
    fn apply(&self, members: &mut BTreeSet<T>) {
        match self {
            Reconfig::Join(p) => members.insert(p.clone()),
            Reconfig::Leave(p) => members.remove(p),
        };
    }
}

impl<T: Proposition> Membership<T> {
    pub fn from(
        secret_key: (NodeId, SecretKeyShare),
        elders: PublicKeySet,
        n_elders: usize,
    ) -> Self {
        Membership::<T> {
            consensus: Consensus::<Reconfig<T>>::from(secret_key, elders, n_elders),
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: Default::default(),
            history: BTreeMap::new(),
        }
    }

    pub fn force_join(&mut self, actor: T) {
        let forced_reconfigs = self.forced_reconfigs.entry(self.gen).or_default();

        // remove any leave reconfigs for this actor
        forced_reconfigs.remove(&Reconfig::Leave(actor.clone()));
        forced_reconfigs.insert(Reconfig::Join(actor));
    }

    pub fn force_leave(&mut self, actor: T) {
        let forced_reconfigs = self.forced_reconfigs.entry(self.gen).or_default();

        // remove any leave reconfigs for this actor
        forced_reconfigs.remove(&Reconfig::Join(actor.clone()));
        forced_reconfigs.insert(Reconfig::Leave(actor));
    }

    pub fn members(&self, gen: Generation) -> Result<BTreeSet<T>> {
        let mut members = BTreeSet::new();

        self.forced_reconfigs
            .get(&0) // forced reconfigs at generation 0
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .for_each(|r| r.apply(&mut members));

        if gen == 0 {
            return Ok(members);
        }

        for (history_gen, history_entry) in self.history.iter() {
            self.forced_reconfigs
                .get(history_gen)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .for_each(|r| r.apply(&mut members));

            for (reconfig, _sig) in history_entry.proposals.iter() {
                reconfig.apply(&mut members);
            }

            if history_gen == &gen {
                return Ok(members);
            }
        }

        Err(Error::InvalidGeneration(gen))
    }

    pub fn propose(&mut self, reconfig: Reconfig<T>) -> Result<SignedVote<Reconfig<T>>> {
        let vote = Vote {
            gen: self.gen + 1,
            ballot: Ballot::Propose(reconfig),
            faults: self.consensus.faults(),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_signed_vote(&signed_vote)?;
        self.consensus
            .detect_byzantine_voters(&signed_vote)
            .map_err(|_| Error::AttemptedFaultyProposal)?;
        Ok(self.cast_vote(signed_vote))
    }

    pub fn anti_entropy(&self, from_gen: Generation) -> Result<Vec<SignedVote<Reconfig<T>>>> {
        info!("[MBR] anti-entropy from gen {}", from_gen);

        let mut msgs = self
            .history
            .iter() // history is a BTreeSet, .iter() is ordered by generation
            .filter(|(gen, _)| **gen > from_gen)
            .map(|(gen, history_entry)| {
                self.consensus
                    .build_super_majority_vote(history_entry.votes.clone(), *gen)
            })
            .collect::<Result<Vec<_>>>()?;

        // include the current in-progres votes as well.
        msgs.extend(self.consensus.votes.values().cloned());

        Ok(msgs)
    }

    pub fn id(&self) -> NodeId {
        self.consensus.id()
    }

    pub fn handle_signed_vote(
        &mut self,
        signed_vote: SignedVote<Reconfig<T>>,
    ) -> Result<VoteResponse<Reconfig<T>>> {
        self.validate_signed_vote(&signed_vote)?;
        self.log_signed_vote(&signed_vote);

        let vote_response = self
            .consensus
            .handle_signed_vote(signed_vote, self.pending_gen)?;

        match &vote_response {
            VoteResponse::Broadcast(vote) => {
                self.pending_gen = vote.vote.gen;
            }
            VoteResponse::Decided {
                votes,
                proposals,
                faults,
            } => {
                self.history.insert(
                    self.pending_gen,
                    HistoryEntry {
                        votes: votes.clone(),
                        proposals: proposals.clone(),
                        faults: faults.clone(),
                    },
                );
                self.gen = self.pending_gen;
                // clear our pending votes
                self.consensus.votes = Default::default();
            }
            VoteResponse::WaitingForMoreVotes => {}
        }

        Ok(vote_response)
    }

    pub fn sign_vote(&self, vote: Vote<Reconfig<T>>) -> Result<SignedVote<Reconfig<T>>> {
        self.consensus.sign_vote(vote)
    }

    pub fn cast_vote(&mut self, signed_vote: SignedVote<Reconfig<T>>) -> SignedVote<Reconfig<T>> {
        self.log_signed_vote(&signed_vote);
        signed_vote
    }

    fn log_signed_vote(&mut self, signed_vote: &SignedVote<Reconfig<T>>) {
        self.pending_gen = signed_vote.vote.gen;
        self.consensus.log_signed_vote(signed_vote);
    }

    pub fn count_votes(
        &self,
        votes: &BTreeSet<SignedVote<Reconfig<T>>>,
    ) -> BTreeMap<BTreeSet<Reconfig<T>>, usize> {
        self.consensus.count_votes(votes)
    }

    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<Reconfig<T>>) -> Result<()> {
        if signed_vote.vote.gen != self.gen + 1 {
            return Err(Error::VoteNotForNextGeneration {
                vote_gen: signed_vote.vote.gen,
                gen: self.gen,
                pending_gen: self.pending_gen,
            });
        }

        signed_vote
            .proposals()
            .into_iter()
            .try_for_each(|reconfig| self.validate_reconfig(reconfig))?;

        self.consensus.validate_signed_vote(signed_vote)
    }

    pub fn validate_reconfig(&self, reconfig: Reconfig<T>) -> Result<()> {
        let members = self.members(self.gen)?;
        match reconfig {
            Reconfig::Join(actor) => {
                if members.contains(&actor) {
                    Err(Error::JoinRequestForExistingMember)
                } else if members.len() >= SOFT_MAX_MEMBERS {
                    Err(Error::MembersAtCapacity)
                } else {
                    Ok(())
                }
            }
            Reconfig::Leave(actor) => {
                if !members.contains(&actor) {
                    Err(Error::LeaveRequestForNonMember)
                } else {
                    Ok(())
                }
            }
        }
    }
}
