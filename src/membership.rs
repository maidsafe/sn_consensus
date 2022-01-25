use std::collections::{BTreeMap, BTreeSet};

use core::fmt::Debug;
use log::info;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};
use crate::{PublicKeyShare, SecretKeyShare};

use crate::consensus::State;
use crate::vote::{Ballot, Proposition, UnsignedVote, Vote};

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;

#[derive(Debug)]
pub struct MembershipState<T: Proposition> {
    pub state: State<T>,
    // TODO: we need faulty elder detection
    // pub faulty_elders: BTreeMap<PublicKeyShare, BTreeSet<Vote<T>>>,
    pub gen: Generation,
    pub pending_gen: Generation,
    pub forced_reconfigs: BTreeMap<Generation, BTreeSet<Reconfig<T>>>, // TODO: change to bootstrap members
    pub history: BTreeMap<Generation, Vote<T>>, // for onboarding new procs, the vote proving super majority
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

impl<T: Proposition> MembershipState<T> {
    pub fn from(secret_key: SecretKeyShare, elders: BTreeSet<PublicKeyShare>) -> Self {
        MembershipState {
            state: State::from(secret_key, elders),
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: Default::default(),
            history: Default::default(),
        }
    }

    pub fn random(rng: impl Rng + CryptoRng) -> Self {
        MembershipState {
            state: State::random(rng),
            gen: 0,
            pending_gen: 0,
            forced_reconfigs: Default::default(),
            history: Default::default(),
        }
    }

    pub fn force_join(&mut self, actor: T) {
        let forced_reconfigs = self.forced_reconfigs.entry(self.gen).or_default();

        // remove any leave reconfigs for this actor
        forced_reconfigs.remove(&Reconfig::Leave(actor));
        forced_reconfigs.insert(Reconfig::Join(actor));
    }

    pub fn force_leave(&mut self, actor: T) {
        let forced_reconfigs = self.forced_reconfigs.entry(self.gen).or_default();

        // remove any leave reconfigs for this actor
        forced_reconfigs.remove(&Reconfig::Join(actor));
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

    pub fn propose(&mut self, reconfig: Reconfig<T>) -> Result<Vote<T>> {
        let vote = UnsignedVote {
            gen: self.gen + 1,
            ballot: Ballot::Propose(reconfig),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_signed_vote(&signed_vote)?;
        Ok(self.cast_vote(signed_vote))
    }

    pub fn anti_entropy(&self, from_gen: Generation) -> Vec<Vote<T>> {
        info!("[MBR] anti-entropy from gen {}", from_gen);

        let mut msgs = Vec::from_iter(
            self.history
                .iter() // history is a BTreeSet, .iter() is ordered by generation
                .filter(|(gen, _)| **gen > from_gen)
                .map(|(_, membership_proof)| membership_proof.clone()),
        );

        // include the current in-progres votes as well.
        msgs.extend(self.state.votes.values().cloned());

        msgs
    }

    fn resolve_votes(&self, votes: &BTreeSet<Vote<T>>) -> BTreeSet<Reconfig<T>> {
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
