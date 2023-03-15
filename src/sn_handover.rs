use std::collections::BTreeMap;

use blsttc::{PublicKeySet, SecretKeyShare, Signature};
use core::fmt::Debug;
use log::info;

use crate::consensus::{Consensus, VoteResponse};
use crate::vote::{Ballot, Proposition, SignedVote, Vote, simplify_votes};
use crate::{Error, NodeId, Result};

pub type UniqueSectionId = u64;

#[derive(Debug)]
pub struct Handover<T: Proposition> {
    pub consensus: Consensus<T>,
    pub gen: UniqueSectionId,
}

impl<T: Proposition> Handover<T> {
    pub fn from(
        secret_key: (NodeId, SecretKeyShare),
        elders: PublicKeySet,
        n_elders: usize,
        gen: UniqueSectionId,
    ) -> Self {
        Handover::<T> {
            consensus: Consensus::<T>::from(secret_key, elders, n_elders),
            gen,
        }
    }

    pub fn propose(&mut self, proposal: T) -> Result<SignedVote<T>> {
        let vote = Vote {
            gen: self.gen,
            ballot: Ballot::Propose(proposal),
            faults: self.consensus.faults(),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_proposals(&signed_vote)?;
        signed_vote
            .detect_byzantine_faults(
                &self.consensus.elders,
                &self.consensus.votes,
                &self.consensus.processed_votes_cache,
            )
            .map_err(|_| Error::AttemptedFaultyProposal)?;
        self.cast_vote(signed_vote)
    }

    // Get someone up to speed on our view of the current votes
    pub fn anti_entropy(&self) -> Result<Vec<SignedVote<T>>> {
        info!("[HDVR] anti-entropy from {:?}", self.id());

        if let Some(_decision) = self.consensus.decision.as_ref() {
            let vote = self.consensus.build_super_majority_vote(
                self.consensus.votes.values().cloned().collect(),
                self.consensus.faults.values().cloned().collect(),
                self.gen,
            )?;
            Ok(vec![vote])
        } else {
            Ok(Vec::from_iter(simplify_votes(&self.consensus.votes.values().cloned().collect())))
        }
    }

    pub fn resolve_votes<'a>(&self, proposals: &'a BTreeMap<T, Signature>) -> Option<&'a T> {
        // we need to choose one deterministically
        // proposals are comparable because they impl Ord so we arbitrarily pick the max
        proposals.keys().max()
    }

    pub fn id(&self) -> NodeId {
        self.consensus.id()
    }

    pub fn handle_signed_vote(&mut self, signed_vote: SignedVote<T>) -> Result<VoteResponse<T>> {
        self.validate_proposals(&signed_vote)?;

        self.consensus.handle_signed_vote(signed_vote)
    }

    pub fn sign_vote(&self, vote: Vote<T>) -> Result<SignedVote<T>> {
        self.consensus.sign_vote(vote)
    }

    pub fn cast_vote(&mut self, signed_vote: SignedVote<T>) -> Result<SignedVote<T>> {
        self.consensus.cast_vote(signed_vote)
    }

    pub fn validate_proposals(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        if signed_vote.vote.gen != self.gen {
            return Err(Error::BadGeneration {
                requested_gen: signed_vote.vote.gen,
                gen: self.gen,
            });
        }

        signed_vote
            .proposals()
            .into_iter()
            .try_for_each(|prop| self.validate_proposal(prop))
    }

    // Placeholder for now, may be useful for sn_node
    pub fn validate_proposal(&self, _proposal: T) -> Result<()> {
        Ok(())
    }
}
