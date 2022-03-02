use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, SecretKeyShare};
use core::fmt::Debug;
use log::info;
use serde::{Deserialize, Serialize};

use crate::consensus::{Consensus, VoteResponse};
use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::{Error, NodeId, Result};

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;

#[derive(Debug)]
pub struct Membership<T: Proposition> {
    pub consensus: Consensus<Reconfig<T>>,
    pub gen: Generation,
    pub forced_reconfigs: BTreeMap<Generation, BTreeSet<Reconfig<T>>>,
    pub history: BTreeMap<Generation, Consensus<Reconfig<T>>>,
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
        Membership {
            consensus: Consensus::from(secret_key, elders, n_elders),
            gen: 0,
            forced_reconfigs: Default::default(),
            history: BTreeMap::default(),
        }
    }

    pub fn consensus_at_gen(&self, gen: Generation) -> Option<&Consensus<Reconfig<T>>> {
        if gen == self.gen + 1 {
            Some(&self.consensus)
        } else {
            self.history.get(&gen)
        }
    }

    pub fn consensus_at_gen_mut(&mut self, gen: Generation) -> Option<&mut Consensus<Reconfig<T>>> {
        if gen == self.gen + 1 {
            Some(&mut self.consensus)
        } else {
            self.history.get_mut(&gen)
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

        for (history_gen, consensus) in self.history.iter() {
            self.forced_reconfigs
                .get(history_gen)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .for_each(|r| r.apply(&mut members));

            let decision = if let Some(decision) = consensus.decision.as_ref() {
                decision
            } else {
                panic!(
                    "historical consensus entry without decision {}: {:?}",
                    history_gen, consensus
                );
            };

            for (reconfig, _sig) in decision.proposals.iter() {
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
        self.cast_vote(signed_vote)
    }

    pub fn anti_entropy(&self, from_gen: Generation) -> Result<Vec<SignedVote<Reconfig<T>>>> {
        info!("[MBR] anti-entropy from gen {}", from_gen);

        let mut msgs = self
            .history
            .iter() // history is a BTreeSet, .iter() is ordered by generation
            .filter(|(gen, _)| **gen > from_gen)
            .filter_map(|(gen, c)| c.decision.clone().map(|d| (gen, c, d)))
            .map(|(gen, c, decision)| {
                c.build_super_majority_vote(decision.votes, decision.faults, *gen)
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

        let vote_gen = signed_vote.vote.gen;

        let consensus = self.consensus_at_gen_mut(vote_gen).unwrap();
        let vote_response = consensus.handle_signed_vote(signed_vote)?;

        if consensus.decision.is_some() && vote_gen == self.gen + 1 {
            let next_consensus = Consensus::from(
                self.consensus.secret_key.clone(),
                self.consensus.elders.clone(),
                self.consensus.n_elders,
            );

            let decided_consensus = std::mem::replace(&mut self.consensus, next_consensus);
            self.history.insert(vote_gen, decided_consensus);
            self.gen = vote_gen
        }

        Ok(vote_response)
    }

    pub fn sign_vote(&self, vote: Vote<Reconfig<T>>) -> Result<SignedVote<Reconfig<T>>> {
        self.consensus.sign_vote(vote)
    }

    pub fn cast_vote(
        &mut self,
        signed_vote: SignedVote<Reconfig<T>>,
    ) -> Result<SignedVote<Reconfig<T>>> {
        self.consensus.cast_vote(&signed_vote)?;
        Ok(signed_vote)
    }

    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<Reconfig<T>>) -> Result<()> {
        if let Some(c) = self.consensus_at_gen(signed_vote.vote.gen) {
            c.validate_signed_vote(signed_vote)?;
        } else {
            return Err(Error::VoteForBadGeneration {
                vote_gen: signed_vote.vote.gen,
                gen: self.gen,
            });
        }

        signed_vote
            .proposals()
            .into_iter()
            .try_for_each(|reconfig| self.validate_reconfig(reconfig, signed_vote.vote.gen))
    }

    pub fn validate_reconfig(&self, reconfig: Reconfig<T>, gen: Generation) -> Result<()> {
        assert!(gen > 0);
        let members = self.members(gen - 1)?;
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
