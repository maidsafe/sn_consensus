use std::collections::{BTreeMap, BTreeSet};

use blsttc::SignatureShare;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

use crate::sn_membership::Generation;
use crate::NodeId;

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

fn simplify_votes<T: Proposition>(
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

impl<T: Proposition> Ballot<T> {
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
}

impl<T: Proposition> Debug for Vote<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "G{}-{:?}", self.gen, self.ballot)
    }
}

impl<T: Proposition> Vote<T> {
    pub fn is_super_majority_ballot(&self) -> bool {
        matches!(self.ballot, Ballot::SuperMajority { .. })
    }

    pub fn proposals(&self) -> BTreeSet<T> {
        match &self.ballot {
            Ballot::Propose(proposal) => BTreeSet::from_iter([proposal.clone()]),
            Ballot::Merge(votes) | Ballot::SuperMajority { votes, .. } => {
                // TAI: use proposals instead of recursing on SuperMajority?
                BTreeSet::from_iter(votes.iter().flat_map(SignedVote::proposals))
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
    pub fn unpack_votes(&self) -> BTreeSet<&Self> {
        match &self.vote.ballot {
            Ballot::Propose(_) => BTreeSet::from_iter([self]),
            Ballot::Merge(votes) | Ballot::SuperMajority { votes, .. } => BTreeSet::from_iter(
                std::iter::once(self).chain(votes.iter().flat_map(Self::unpack_votes)),
            ),
        }
    }

    pub fn proposals(&self) -> BTreeSet<T> {
        self.vote.proposals()
    }

    pub fn supersedes(&self, signed_vote: &Self) -> bool {
        if self == signed_vote {
            true
        } else {
            match &self.vote.ballot {
                Ballot::Propose(_) => false,
                Ballot::Merge(votes) | Ballot::SuperMajority { votes, .. } => {
                    votes.iter().any(|v| v.supersedes(signed_vote))
                }
            }
        }
    }

    pub fn strict_supersedes(&self, signed_vote: &Self) -> bool {
        self != signed_vote && self.supersedes(signed_vote)
    }
}
