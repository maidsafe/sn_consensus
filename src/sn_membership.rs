use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeyShare, SecretKeyShare};
use core::fmt::Debug;
use log::info;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::consensus::Consensus;
use crate::{Error, Result};

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;

#[derive(Debug)]
pub struct Membership<T: Proposition> {
    pub consensus: Consensus::<Reconfig<T>>,
    // TODO: we need faulty elder detection
    // pub faulty_elders: BTreeMap<PublicKeyShare, BTreeSet<SignedVote<Reconfig<T>>>>,
    pub gen: Generation,
    pub pending_gen: Generation,
    pub forced_reconfigs: BTreeMap<Generation, BTreeSet<Reconfig<T>>>, // TODO: change to bootstrap members
    pub history: BTreeMap<Generation, SignedVote<Reconfig<T>>>, // for onboarding new procs, the vote proving super majority
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
    fn apply(self, members: &mut BTreeSet<T>) {
        match self {
            Reconfig::Join(p) => members.insert(p),
            Reconfig::Leave(p) => members.remove(&p),
        };
    }
}

impl<T: Proposition> Membership<T> {
    pub fn from(secret_key: SecretKeyShare, elders: BTreeSet<PublicKeyShare>) -> Self {
        Membership::<T> {
            consensus: Consensus::<Reconfig<T>>::from(secret_key, elders),
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: Default::default(),
            history: Default::default(),
        }
    }

    pub fn random(rng: impl Rng + CryptoRng) -> Self {
        Membership::<T> {
            consensus: Consensus::<Reconfig<T>>::random(rng),
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: Default::default(),
            history: Default::default(),
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

        for (history_gen, signed_vote) in self.history.iter() {
            self.forced_reconfigs
                .get(history_gen)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .for_each(|r| r.apply(&mut members));

            let supermajority_votes = match &signed_vote.vote.ballot {
                Ballot::SuperMajority(votes) => votes,
                _ => {
                    return Err(Error::InvalidVoteInHistory);
                }
            };

            self.resolve_votes(supermajority_votes)
                .into_iter()
                .for_each(|r| r.apply(&mut members));

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
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_signed_vote(&signed_vote)?;
        Ok(self.cast_vote(signed_vote))
    }

    pub fn anti_entropy(&self, from_gen: Generation) -> Vec<SignedVote<Reconfig<T>>> {
        info!("[MBR] anti-entropy from gen {}", from_gen);

        let mut msgs = Vec::from_iter(
            self.history
                .iter() // history is a BTreeSet, .iter() is ordered by generation
                .filter(|(gen, _)| **gen > from_gen)
                .map(|(_, membership_proof)| membership_proof.clone()),
        );

        // include the current in-progres votes as well.
        msgs.extend(self.consensus.votes.values().cloned());

        msgs
    }

    fn resolve_votes(&self, votes: &BTreeSet<SignedVote<Reconfig<T>>>) -> BTreeSet<Reconfig<T>> {
        let (winning_reconfigs, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .unwrap_or_default();

        winning_reconfigs
    }

    pub fn public_key_share(&self) -> PublicKeyShare {
        self.consensus.public_key_share()
    }

    pub fn handle_signed_vote(
        &mut self,
        signed_vote: SignedVote<Reconfig<T>>,
    ) -> Result<Option<SignedVote<Reconfig<T>>>> {
        self.validate_signed_vote(&signed_vote)?;

        let (vote, consensus_proof) = self.consensus.handle_signed_vote(signed_vote, self.pending_gen)?;
        if let Some(proof) = consensus_proof {
            self.history.insert(self.pending_gen, proof);
            self.gen = self.pending_gen;
        }

        Ok(vote)
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
        signed_vote.validate_signature()?;
        self.validate_vote(&signed_vote.vote)?;
        self.consensus.validate_is_elder(signed_vote.voter)?;
        self.consensus.validate_vote_supersedes_existing_vote(signed_vote)?;
        self.consensus.validate_voters_have_not_changed_proposals(signed_vote)?;
        Ok(())
    }

    fn validate_vote(&self, vote: &Vote<Reconfig<T>>) -> Result<()> {
        if vote.gen != self.gen + 1 {
            return Err(Error::VoteNotForNextGeneration {
                vote_gen: vote.gen,
                gen: self.gen,
                pending_gen: self.pending_gen,
            });
        }

        match &vote.ballot {
            Ballot::Propose(reconfig) => self.validate_reconfig(reconfig.clone()),
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
