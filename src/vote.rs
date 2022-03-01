use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeySet, SignatureShare};
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::sn_membership::Generation;
use crate::{Fault, NodeId, Result};

pub trait Proposition: Ord + Clone + Debug + Serialize {}
impl<T: Ord + Clone + Debug + Serialize> Proposition for T {}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ballot<T: Proposition> {
    Propose(T),
    Merge(BTreeSet<SignedVote<T>>),
    SuperMajority {
        votes: BTreeSet<SignedVote<T>>,
        proposals: BTreeMap<T, (NodeId, SignatureShare)>,
    },
}

impl<T: Proposition> Debug for Ballot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ballot::Propose(r) => write!(f, "P({:?})", r),
            Ballot::Merge(votes) => write!(f, "M{:?}", votes),
            Ballot::SuperMajority { votes, proposals } => write!(
                f,
                "SM{:?}-{:?}",
                votes,
                BTreeSet::from_iter(proposals.keys())
            ),
        }
    }
}

pub fn simplify_votes<T: Proposition>(
    signed_votes: &BTreeSet<SignedVote<T>>,
) -> BTreeSet<SignedVote<T>> {
    let mut simpler_votes = BTreeSet::new();
    for v in signed_votes.iter() {
        let this_vote_is_superseded = signed_votes
            .iter()
            .filter(|other_v| other_v != &v)
            .any(|other_v| other_v.supersedes(v));

        if !this_vote_is_superseded {
            simpler_votes.insert(v.clone());
        }
    }
    simpler_votes
}

pub fn proposals<T: Proposition>(
    votes: &BTreeSet<SignedVote<T>>,
    known_faulty: &BTreeSet<NodeId>,
) -> BTreeSet<T> {
    BTreeSet::from_iter(
        votes
            .iter()
            .flat_map(SignedVote::unpack_votes)
            .filter(|v| !known_faulty.contains(&v.voter))
            .filter_map(|v| v.vote.ballot.as_proposal())
            .cloned(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Candidate<T> {
    pub proposals: BTreeSet<T>,
    pub faulty: BTreeSet<NodeId>,
}

type SignatureSharesByVoter<T> = BTreeMap<NodeId, BTreeMap<T, SignatureShare>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteCount<T> {
    pub candidates: BTreeMap<Candidate<T>, usize>,
    pub super_majorities: BTreeMap<Candidate<T>, SignatureSharesByVoter<T>>,
    pub voters: BTreeSet<NodeId>,
}

impl<T> Default for VoteCount<T> {
    fn default() -> Self {
        Self {
            candidates: Default::default(),
            super_majorities: Default::default(),
            voters: Default::default(),
        }
    }
}

impl<T: Proposition> VoteCount<T> {
    pub fn count(votes: impl IntoIterator<Item = impl Borrow<SignedVote<T>>>) -> Self {
        let mut count: VoteCount<T> = VoteCount::default();
        let mut counted: BTreeSet<SignatureShare> = Default::default();

        for vote in votes.into_iter() {
            for unpacked_vote in vote.borrow().unpack_votes() {
                if counted.contains(&unpacked_vote.sig) {
                    continue;
                }
                counted.insert(unpacked_vote.sig.clone());

                count.voters.insert(unpacked_vote.voter);
                let candidate = unpacked_vote.vote.candidate();

                match &unpacked_vote.vote.ballot {
                    Ballot::SuperMajority { proposals, .. } => {
                        let shares = count.super_majorities.entry(candidate).or_default();
                        for (t, (id, sig)) in proposals {
                            shares
                                .entry(*id)
                                .or_default()
                                .insert(t.clone(), sig.clone());
                        }
                    }
                    _ => {
                        let c = count.candidates.entry(candidate).or_default();
                        *c += 1;
                    }
                }
            }
        }

        count
    }

    pub fn candidates_with_most_votes(&self) -> Option<(&Candidate<T>, usize)> {
        self.candidates
            .iter()
            .map(|(candidates, c)| (candidates, *c))
            .chain(
                self.super_majorities
                    .iter()
                    .map(|(candidates, shares)| (candidates, shares.len())),
            )
            .max_by_key(|(_, c)| *c)
    }

    pub fn super_majorities_with_most_votes(
        &self,
    ) -> Option<(&Candidate<T>, &SignatureSharesByVoter<T>)> {
        self.super_majorities
            .iter()
            .max_by_key(|(_, shares)| shares.len())
    }
}

impl<T: Proposition> Ballot<T> {
    pub fn as_proposal(&self) -> Option<&T> {
        match &self {
            Ballot::Propose(p) => Some(p),
            _ => None,
        }
    }

    #[must_use]
    pub fn simplify(&self) -> Self {
        match &self {
            Ballot::Propose(_) => self.clone(), // already in simplest form
            Ballot::Merge(votes) => Ballot::Merge(simplify_votes(votes)),
            Ballot::SuperMajority { votes, proposals } => Ballot::SuperMajority {
                votes: simplify_votes(votes),
                proposals: proposals.clone(),
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vote<T: Proposition> {
    pub gen: Generation,
    pub ballot: Ballot<T>,
    pub faults: BTreeSet<Fault<T>>,
}

impl<T: Proposition> Debug for Vote<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "G{}-{:?}", self.gen, self.ballot)?;

        if !self.faults.is_empty() {
            write!(f, "-F{:?}", self.faults)?;
        }
        Ok(())
    }
}

impl<T: Proposition> Vote<T> {
    pub fn candidate(&self) -> Candidate<T> {
        Candidate {
            proposals: self.proposals(),
            faulty: self.known_faulty(),
        }
    }

    pub fn is_super_majority_ballot(&self) -> bool {
        matches!(self.ballot, Ballot::SuperMajority { .. })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&self)?)
    }

    pub fn known_faulty(&self) -> BTreeSet<NodeId> {
        BTreeSet::from_iter(self.faults.iter().map(Fault::voter_at_fault))
    }

    pub fn proposals(&self) -> BTreeSet<T> {
        self.proposals_with_known_faults(&self.known_faulty())
    }

    pub fn proposals_with_known_faults(&self, known_faulty: &BTreeSet<NodeId>) -> BTreeSet<T> {
        match &self.ballot {
            Ballot::Propose(proposal) => BTreeSet::from_iter([proposal.clone()]),
            Ballot::Merge(votes) | Ballot::SuperMajority { votes, .. } => {
                // TAI: use proposals instead of recursing on SuperMajority?
                proposals(votes, known_faulty)
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignedVote<T: Proposition> {
    pub vote: Vote<T>,
    pub voter: NodeId,
    pub sig: SignatureShare,
}

impl<T: Proposition> Debug for SignedVote<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}@{}", self.vote, self.voter)
    }
}

impl<T: Proposition> SignedVote<T> {
    pub fn validate_signature(&self, voters: &PublicKeySet) -> Result<()> {
        crate::verify_sig_share(&self.vote, &self.sig, self.voter, voters)
    }

    pub fn unpack_votes(&self) -> Box<dyn Iterator<Item = &Self> + '_> {
        match &self.vote.ballot {
            Ballot::Propose(_) => Box::new(std::iter::once(self)),
            Ballot::Merge(votes) | Ballot::SuperMajority { votes, .. } => {
                Box::new(std::iter::once(self).chain(votes.iter().flat_map(Self::unpack_votes)))
            }
        }
    }

    pub fn proposals(&self) -> BTreeSet<T> {
        self.vote.proposals()
    }

    pub fn supersedes(&self, other: &Self) -> bool {
        let our_known_faulty = self.vote.known_faulty();
        let other_known_faulty = other.vote.known_faulty();

        if (&self.voter, self.vote.gen, &self.vote.ballot)
            == (&other.voter, other.vote.gen, &other.vote.ballot)
            && our_known_faulty.is_superset(&other_known_faulty)
        {
            true
        } else {
            match &self.vote.ballot {
                Ballot::Propose(_) => false, // equality is already checked above
                Ballot::Merge(votes) | Ballot::SuperMajority { votes, .. } => {
                    votes.iter().any(|v| v.supersedes(other))
                }
            }
        }
    }

    pub fn strict_supersedes(&self, signed_vote: &Self) -> bool {
        self != signed_vote && self.supersedes(signed_vote)
    }
}
