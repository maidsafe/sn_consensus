use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeyShare, SecretKeyShare, SignatureShare};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};
use core::fmt::Debug;
use log::info;

const SOFT_MAX_MEMBERS: usize = 7;
pub type Generation = u64;
pub trait Name: Ord + Clone + Debug + Serialize {}
impl<T: Ord + Clone + Debug + Serialize> Name for T {}

#[derive(Debug)]
pub struct State<T: Name> {
    pub elders: BTreeSet<PublicKeyShare>,
    pub secret_key: SecretKeyShare,
    pub gen: Generation,
    pub pending_gen: Generation,
    pub forced_reconfigs: BTreeMap<Generation, BTreeSet<Reconfig<T>>>, // TODO: change to bootstrap members
    pub history: BTreeMap<Generation, SignedVote<T>>, // for onboarding new procs, the vote proving super majority
    pub votes: BTreeMap<PublicKeyShare, SignedVote<T>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Reconfig<T: Name> {
    Join(T),
    Leave(T),
}

impl<T: Name> Debug for Reconfig<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reconfig::Join(a) => write!(f, "J{:?}", a),
            Reconfig::Leave(a) => write!(f, "L{:?}", a),
        }
    }
}

impl<T: Name> Reconfig<T> {
    fn apply(self, members: &mut BTreeSet<T>) {
        match self {
            Reconfig::Join(p) => members.insert(p),
            Reconfig::Leave(p) => members.remove(&p),
        };
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ballot<T: Name> {
    Propose(Reconfig<T>),
    Merge(BTreeSet<SignedVote<T>>),
    SuperMajority(BTreeSet<SignedVote<T>>),
}

impl<T: Name> Debug for Ballot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ballot::Propose(r) => write!(f, "P({:?})", r),
            Ballot::Merge(votes) => write!(f, "M{:?}", votes),
            Ballot::SuperMajority(votes) => write!(f, "SM{:?}", votes),
        }
    }
}

fn simplify_votes<T: Name>(signed_votes: &BTreeSet<SignedVote<T>>) -> BTreeSet<SignedVote<T>> {
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

impl<T: Name> Ballot<T> {
    fn simplify(&self) -> Self {
        match &self {
            Ballot::Propose(_) => self.clone(), // already in simplest form
            Ballot::Merge(votes) => Ballot::Merge(simplify_votes(votes)),
            Ballot::SuperMajority(votes) => Ballot::SuperMajority(simplify_votes(votes)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vote<T: Name> {
    pub gen: Generation,
    pub ballot: Ballot<T>,
}

impl<T: Name> Debug for Vote<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "G{}-{:?}", self.gen, self.ballot)
    }
}

impl<T: Name> Vote<T> {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(&self.ballot, &self.gen))?)
    }

    pub fn is_super_majority_ballot(&self) -> bool {
        matches!(self.ballot, Ballot::SuperMajority(_))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignedVote<T: Name> {
    pub vote: Vote<T>,
    pub voter: PublicKeyShare,
    pub sig: SignatureShare,
}

impl<T: Name> Debug for SignedVote<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}@{:?}", self.vote, self.voter)
    }
}

impl<T: Name> SignedVote<T> {
    fn validate_signature(&self) -> Result<()> {
        if self.voter.verify(&self.sig, &self.vote.to_bytes()?) {
            Ok(())
        } else {
            Err(Error::InvalidElderSignature)
        }
    }

    fn unpack_votes(&self) -> BTreeSet<&Self> {
        match &self.vote.ballot {
            Ballot::Propose(_) => BTreeSet::from_iter([self]),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => BTreeSet::from_iter(
                std::iter::once(self).chain(votes.iter().flat_map(Self::unpack_votes)),
            ),
        }
    }

    fn reconfigs(&self) -> BTreeSet<(PublicKeyShare, Reconfig<T>)> {
        match &self.vote.ballot {
            Ballot::Propose(reconfig) => BTreeSet::from_iter([(self.voter, reconfig.clone())]),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                BTreeSet::from_iter(votes.iter().flat_map(Self::reconfigs))
            }
        }
    }

    fn supersedes(&self, signed_vote: &Self) -> bool {
        if self == signed_vote {
            true
        } else {
            match &self.vote.ballot {
                Ballot::Propose(_) => false,
                Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                    votes.iter().any(|v| v.supersedes(signed_vote))
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteMsg<T: Name> {
    pub vote: SignedVote<T>,
    pub dest: PublicKeyShare,
}

impl<T: Name> State<T> {
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

    pub fn public_key_share(&self) -> PublicKeyShare {
        self.secret_key.public_key_share()
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

    pub fn propose(&mut self, reconfig: Reconfig<T>) -> Result<Vec<VoteMsg<T>>> {
        let vote = Vote {
            gen: self.gen + 1,
            ballot: Ballot::Propose(reconfig),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_signed_vote(&signed_vote)?;
        self.cast_vote(signed_vote)
    }

    pub fn anti_entropy(&self, from_gen: Generation, actor: PublicKeyShare) -> Vec<VoteMsg<T>> {
        info!(
            "[MBR] anti-entropy for {:?}.{} from {:?}",
            actor,
            from_gen,
            self.public_key_share()
        );

        let mut msgs: Vec<_> = self
            .history
            .iter() // history is a BTreeSet, .iter() is ordered by generation
            .filter(|(gen, _)| **gen > from_gen)
            .map(|(_, membership_proof)| self.send(membership_proof.clone(), actor))
            .collect();

        msgs.extend(self.votes.values().cloned().map(|v| self.send(v, actor)));

        msgs
    }

    pub fn handle_signed_vote(&mut self, signed_vote: SignedVote<T>) -> Result<Vec<VoteMsg<T>>> {
        self.validate_signed_vote(&signed_vote)?;

        self.log_signed_vote(&signed_vote);

        if self.is_split_vote(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected split vote");
            let merge_vote = Vote {
                gen: self.pending_gen,
                ballot: Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            if let Some(our_vote) = self.votes.get(&self.public_key_share()) {
                let reconfigs_we_voted_for =
                    BTreeSet::from_iter(our_vote.reconfigs().into_iter().map(|(_, r)| r));
                let reconfigs_we_would_vote_for: BTreeSet<_> = signed_merge_vote
                    .reconfigs()
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect();

                if reconfigs_we_voted_for == reconfigs_we_would_vote_for {
                    info!("[MBR] This vote didn't add new information, waiting for more votes...");
                    return Ok(vec![]);
                }
            }

            info!("[MBR] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return self.cast_vote(signed_merge_vote);
        }

        if self.is_super_majority_over_super_majorities(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected super majority over super majorities");
            assert!(self.elders.contains(&self.public_key_share()));
            // store a proof of what the network decided in our history so that we can onboard future procs.
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();

            let vote = Vote {
                gen: self.pending_gen,
                ballot,
            };
            let signed_vote = self.sign_vote(vote)?;

            self.history.insert(self.pending_gen, signed_vote);
            // clear our pending votes
            self.votes = Default::default();
            self.gen = self.pending_gen;

            return Ok(vec![]);
        }

        if self.is_super_majority(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected super majority");

            if let Some(our_vote) = self.votes.get(&self.public_key_share()) {
                // We voted during this generation.

                // We may have committed to some reconfigs that is not part of this super majority.
                // This happens when the network was able to form super majority without our vote.
                // We can not change our vote since all we know is that a subset of the network saw
                // super majority. It could still be the case that two disjoint subsets of the network
                // see different super majorities, this case will be resolved by the split vote detection
                // as more messages are delivered.

                let super_majority_reconfigs =
                    self.resolve_votes(&self.votes.values().cloned().collect());

                let we_have_comitted_to_reconfigs_not_in_super_majority = self
                    .resolve_votes(&our_vote.unpack_votes().into_iter().cloned().collect())
                    .into_iter()
                    .any(|r| !super_majority_reconfigs.contains(&r));

                if we_have_comitted_to_reconfigs_not_in_super_majority {
                    info!("[MBR] We have committed to reconfigs that the super majority has not seen, waiting till we either have a split vote or SM/SM");
                    return Ok(vec![]);
                } else if our_vote.vote.is_super_majority_ballot() {
                    info!("[MBR] We've already sent a super majority, waiting till we either have a split vote or SM / SM");
                    return Ok(vec![]);
                }
            }

            info!("[MBR] broadcasting super majority");
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();
            let vote = Vote {
                gen: self.pending_gen,
                ballot,
            };
            let signed_vote = self.sign_vote(vote)?;
            return self.cast_vote(signed_vote);
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.public_key_share()) {
            let signed_vote = self.sign_vote(Vote {
                gen: self.pending_gen,
                ballot: signed_vote.vote.ballot,
            })?;
            return self.cast_vote(signed_vote);
        }

        Ok(vec![])
    }

    pub fn sign_vote(&self, vote: Vote<T>) -> Result<SignedVote<T>> {
        Ok(SignedVote {
            voter: self.public_key_share(),
            sig: self.secret_key.sign(&vote.to_bytes()?),
            vote,
        })
    }

    fn cast_vote(&mut self, signed_vote: SignedVote<T>) -> Result<Vec<VoteMsg<T>>> {
        self.log_signed_vote(&signed_vote);
        self.broadcast(signed_vote)
    }

    fn log_signed_vote(&mut self, signed_vote: &SignedVote<T>) {
        self.pending_gen = signed_vote.vote.gen;
        for vote in signed_vote.unpack_votes() {
            let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
            if vote.supersedes(existing_vote) {
                *existing_vote = vote.clone()
            }
        }
    }

    fn count_votes(
        &self,
        votes: &BTreeSet<SignedVote<T>>,
    ) -> BTreeMap<BTreeSet<Reconfig<T>>, usize> {
        let mut count: BTreeMap<BTreeSet<Reconfig<T>>, usize> = Default::default();

        for vote in votes.iter() {
            let reconfigs =
                BTreeSet::from_iter(vote.reconfigs().into_iter().map(|(_, reconfig)| reconfig));
            let c = count.entry(reconfigs).or_default();
            *c += 1;
        }

        count
    }

    fn is_split_vote(&self, votes: &BTreeSet<SignedVote<T>>) -> Result<bool> {
        let counts = self.count_votes(votes);
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let voters = BTreeSet::from_iter(votes.iter().map(|v| v.voter));
        let remaining_voters = self.elders.difference(&voters).count();

        // give the remaining votes to the reconfigs with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        Ok(
            3 * voters.len() > 2 * self.elders.len()
                && 3 * predicted_votes <= 2 * self.elders.len(),
        )
    }

    fn is_super_majority(&self, votes: &BTreeSet<SignedVote<T>>) -> Result<bool> {
        // TODO: super majority should always just be the largest 7 members
        let most_votes = self
            .count_votes(votes)
            .values()
            .max()
            .cloned()
            .unwrap_or_default();

        Ok(3 * most_votes > 2 * self.elders.len())
    }

    fn is_super_majority_over_super_majorities(
        &self,
        votes: &BTreeSet<SignedVote<T>>,
    ) -> Result<bool> {
        let winning_reconfigs = self.resolve_votes(votes);

        let count_of_super_majorities = votes
            .iter()
            .filter(|v| {
                BTreeSet::from_iter(v.reconfigs().into_iter().map(|(_, r)| r)) == winning_reconfigs
            })
            .filter(|v| v.vote.is_super_majority_ballot())
            .count();

        Ok(3 * count_of_super_majorities > 2 * self.elders.len())
    }

    fn resolve_votes(&self, votes: &BTreeSet<SignedVote<T>>) -> BTreeSet<Reconfig<T>> {
        let (winning_reconfigs, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .unwrap_or_default();

        winning_reconfigs
    }

    fn validate_is_elder(&self, public_key: PublicKeyShare) -> Result<()> {
        if !self.elders.contains(&public_key) {
            Err(Error::NotElder {
                public_key,
                elders: self.elders.clone(),
            })
        } else {
            Ok(())
        }
    }

    fn validate_vote_supersedes_existing_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        if self.votes.contains_key(&signed_vote.voter)
            && !signed_vote.supersedes(&self.votes[&signed_vote.voter])
            && !self.votes[&signed_vote.voter].supersedes(signed_vote)
        {
            Err(Error::ExistingVoteIncompatibleWithNewVote)
        } else {
            Ok(())
        }
    }

    fn validate_voters_have_not_changed_proposals(
        &self,
        signed_vote: &SignedVote<T>,
    ) -> Result<()> {
        // Ensure that nobody is trying to change their reconfig proposals.
        let reconfigs: BTreeSet<(PublicKeyShare, Reconfig<T>)> = self
            .votes
            .values()
            .flat_map(|v| v.reconfigs())
            .chain(signed_vote.reconfigs())
            .collect();

        let voters = BTreeSet::from_iter(reconfigs.iter().map(|(actor, _)| actor));
        if voters.len() != reconfigs.len() {
            Err(Error::VoterChangedVote)
        } else {
            Ok(())
        }
    }

    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        signed_vote.validate_signature()?;
        self.validate_vote(&signed_vote.vote)?;
        self.validate_is_elder(signed_vote.voter)?;
        self.validate_vote_supersedes_existing_vote(signed_vote)?;
        self.validate_voters_have_not_changed_proposals(signed_vote)?;
        Ok(())
    }

    fn validate_vote(&self, vote: &Vote<T>) -> Result<()> {
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
                if !self.is_super_majority(
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

    fn broadcast(&self, signed_vote: SignedVote<T>) -> Result<Vec<VoteMsg<T>>> {
        Ok(self
            .elders
            .iter()
            .cloned()
            .map(|elder| self.send(signed_vote.clone(), elder))
            .collect())
    }

    fn send(&self, vote: SignedVote<T>, dest: PublicKeyShare) -> VoteMsg<T> {
        VoteMsg { vote, dest }
    }
}
