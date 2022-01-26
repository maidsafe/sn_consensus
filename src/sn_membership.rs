use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeyShare, SecretKeyShare};
use core::fmt::Debug;
use log::info;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::{Error, Result};

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;

#[derive(Debug)]
pub struct State<T: Proposition> {
    pub elders: BTreeSet<PublicKeyShare>,
    // TODO: we need faulty elder detection
    // pub faulty_elders: BTreeMap<PublicKeyShare, BTreeSet<SignedVote<T>>>,
    pub secret_key: SecretKeyShare,
    pub gen: Generation,
    pub pending_gen: Generation,
    pub forced_reconfigs: BTreeMap<Generation, BTreeSet<Reconfig<T>>>, // TODO: change to bootstrap members
    pub history: BTreeMap<Generation, SignedVote<T>>, // for onboarding new procs, the vote proving super majority
    pub votes: BTreeMap<PublicKeyShare, SignedVote<T>>,
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

impl<T: Proposition> State<T> {
    pub fn from(secret_key: SecretKeyShare, elders: BTreeSet<PublicKeyShare>) -> Self {
        State {
            elders,
            secret_key,
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: Default::default(),
            history: Default::default(),
            votes: Default::default(),
        }
    }

    pub fn random(mut rng: impl Rng + CryptoRng) -> Self {
        State {
            elders: Default::default(),
            secret_key: rng.gen(),
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: Default::default(),
            history: Default::default(),
            votes: Default::default(),
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

    pub fn propose(&mut self, reconfig: Reconfig<T>) -> Result<SignedVote<T>> {
        let vote = Vote {
            gen: self.gen + 1,
            ballot: Ballot::Propose(reconfig),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_signed_vote(&signed_vote)?;
        Ok(self.cast_vote(signed_vote))
    }

    pub fn anti_entropy(&self, from_gen: Generation) -> Vec<SignedVote<T>> {
        info!("[MBR] anti-entropy from gen {}", from_gen);

        let mut msgs = Vec::from_iter(
            self.history
                .iter() // history is a BTreeSet, .iter() is ordered by generation
                .filter(|(gen, _)| **gen > from_gen)
                .map(|(_, membership_proof)| membership_proof.clone()),
        );

        // include the current in-progres votes as well.
        msgs.extend(self.votes.values().cloned());

        msgs
    }

    fn resolve_votes(&self, votes: &BTreeSet<SignedVote<T>>) -> BTreeSet<Reconfig<T>> {
        let (winning_reconfigs, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .unwrap_or_default();

        winning_reconfigs
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
