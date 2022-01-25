use log::info;
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};

use crate::{Error, Result};
use crate::{PublicKeyShare, SecretKeyShare};

use crate::vote::{Ballot, Proposition, UnsignedVote, Vote};

// TODO tmp to separate files
use crate::membership::{MembershipState, Reconfig};

#[derive(Debug)]
pub struct State<T: Proposition> {
    pub secret_key: SecretKeyShare,
    pub elders: BTreeSet<PublicKeyShare>,
    pub votes: BTreeMap<PublicKeyShare, Vote<T>>,
}

impl<T: Proposition> State<T> {
    pub fn from(secret_key: SecretKeyShare, elders: BTreeSet<PublicKeyShare>) -> Self {
        State::<T> {
            secret_key,
            elders,
            votes: Default::default(),
        }
    }

    pub fn random(mut rng: impl Rng + CryptoRng) -> Self {
        State::<T> {
            secret_key: rng.gen(),
            elders: Default::default(),
            votes: Default::default(),
        }
    }
}

impl<T: Proposition> MembershipState<T> {
    pub fn public_key_share(&self) -> PublicKeyShare {
        self.state.secret_key.public_key_share()
    }

    pub fn handle_signed_vote(&mut self, signed_vote: Vote<T>) -> Result<Option<Vote<T>>> {
        self.validate_signed_vote(&signed_vote)?;

        self.log_signed_vote(&signed_vote);

        if self.is_split_vote(&self.state.votes.values().cloned().collect())? {
            info!("[MBR] Detected split vote");
            let merge_vote = UnsignedVote {
                gen: self.pending_gen,
                ballot: Ballot::Merge(self.state.votes.values().cloned().collect()).simplify(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            if let Some(our_vote) = self.state.votes.get(&self.public_key_share()) {
                let reconfigs_we_voted_for =
                    BTreeSet::from_iter(our_vote.reconfigs().into_iter().map(|(_, r)| r));
                let reconfigs_we_would_vote_for: BTreeSet<_> = signed_merge_vote
                    .reconfigs()
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect();

                if reconfigs_we_voted_for == reconfigs_we_would_vote_for {
                    info!("[MBR] This vote didn't add new information, waiting for more votes...");
                    return Ok(None);
                }
            }

            info!("[MBR] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return Ok(Some(self.cast_vote(signed_merge_vote)));
        }

        if self.is_super_majority_over_super_majorities(
            &self.state.votes.values().cloned().collect(),
        )? {
            info!("[MBR] Detected super majority over super majorities");
            assert!(self.state.elders.contains(&self.public_key_share()));
            // store a proof of what the network decided in our history so that we can onboard future procs.
            let ballot =
                Ballot::SuperMajority(self.state.votes.values().cloned().collect()).simplify();

            let vote = UnsignedVote {
                gen: self.pending_gen,
                ballot,
            };
            let signed_vote = self.sign_vote(vote)?;

            self.history.insert(self.pending_gen, signed_vote);
            // clear our pending votes
            self.state.votes = Default::default();
            self.gen = self.pending_gen;

            return Ok(None);
        }

        if self.is_super_majority(&self.state.votes.values().cloned().collect())? {
            info!("[MBR] Detected super majority");

            if let Some(our_vote) = self.state.votes.get(&self.public_key_share()) {
                // We voted during this generation.

                if our_vote.vote.is_super_majority_ballot() {
                    info!("[MBR] We've already sent a super majority, waiting till we either have a split vote or SM / SM");
                    return Ok(None);
                }
            }

            info!("[MBR] broadcasting super majority");
            let ballot =
                Ballot::SuperMajority(self.state.votes.values().cloned().collect()).simplify();
            let vote = UnsignedVote {
                gen: self.pending_gen,
                ballot,
            };
            let signed_vote = self.sign_vote(vote)?;
            return Ok(Some(self.cast_vote(signed_vote)));
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.state.votes.contains_key(&self.public_key_share()) {
            let signed_vote = self.sign_vote(UnsignedVote {
                gen: self.pending_gen,
                ballot: signed_vote.vote.ballot,
            })?;
            return Ok(Some(self.cast_vote(signed_vote)));
        }

        Ok(None)
    }

    pub fn sign_vote(&self, vote: UnsignedVote<T>) -> Result<Vote<T>> {
        Ok(Vote {
            voter: self.public_key_share(),
            sig: self.state.secret_key.sign(&vote.to_bytes()?),
            vote,
        })
    }

    pub fn cast_vote(&mut self, signed_vote: Vote<T>) -> Vote<T> {
        self.log_signed_vote(&signed_vote);
        signed_vote
    }

    fn log_signed_vote(&mut self, signed_vote: &Vote<T>) {
        self.pending_gen = signed_vote.vote.gen;
        for vote in signed_vote.unpack_votes() {
            let existing_vote = self
                .state
                .votes
                .entry(vote.voter)
                .or_insert_with(|| vote.clone());
            if vote.supersedes(existing_vote) {
                *existing_vote = vote.clone()
            }
        }
    }

    pub fn count_votes(&self, votes: &BTreeSet<Vote<T>>) -> BTreeMap<BTreeSet<Reconfig<T>>, usize> {
        let mut count: BTreeMap<BTreeSet<Reconfig<T>>, usize> = Default::default();

        for vote in votes.iter() {
            let reconfigs =
                BTreeSet::from_iter(vote.reconfigs().into_iter().map(|(_, reconfig)| reconfig));
            let c = count.entry(reconfigs).or_default();
            *c += 1;
        }

        count
    }

    fn is_split_vote(&self, votes: &BTreeSet<Vote<T>>) -> Result<bool> {
        let counts = self.count_votes(votes);
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let voters = BTreeSet::from_iter(votes.iter().map(|v| v.voter));
        let remaining_voters = self.state.elders.difference(&voters).count();

        // give the remaining votes to the reconfigs with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        Ok(3 * voters.len() > 2 * self.state.elders.len()
            && 3 * predicted_votes <= 2 * self.state.elders.len())
    }

    fn is_super_majority(&self, votes: &BTreeSet<Vote<T>>) -> Result<bool> {
        // TODO: super majority should always just be the largest 7 members
        let most_votes = self
            .count_votes(votes)
            .values()
            .max()
            .cloned()
            .unwrap_or_default();

        Ok(3 * most_votes > 2 * self.state.elders.len())
    }

    fn is_super_majority_over_super_majorities(&self, votes: &BTreeSet<Vote<T>>) -> Result<bool> {
        let count_of_agreeing_super_majorities = self
            .count_votes(&BTreeSet::from_iter(
                votes
                    .iter()
                    .filter(|v| v.vote.is_super_majority_ballot())
                    .cloned(),
            ))
            .into_iter()
            .map(|(_, count)| count)
            .max()
            .unwrap_or(0);

        Ok(3 * count_of_agreeing_super_majorities > 2 * self.state.elders.len())
    }

    fn validate_is_elder(&self, public_key: PublicKeyShare) -> Result<()> {
        if !self.state.elders.contains(&public_key) {
            Err(Error::NotElder {
                public_key,
                elders: self.state.elders.clone(),
            })
        } else {
            Ok(())
        }
    }

    fn validate_vote_supersedes_existing_vote(&self, signed_vote: &Vote<T>) -> Result<()> {
        if self.state.votes.contains_key(&signed_vote.voter)
            && !signed_vote.supersedes(&self.state.votes[&signed_vote.voter])
            && !self.state.votes[&signed_vote.voter].supersedes(signed_vote)
        {
            Err(Error::ExistingVoteIncompatibleWithNewVote)
        } else {
            Ok(())
        }
    }

    fn validate_voters_have_not_changed_proposals(&self, signed_vote: &Vote<T>) -> Result<()> {
        // Ensure that nobody is trying to change their reconfig proposals.
        let reconfigs: BTreeSet<(PublicKeyShare, Reconfig<T>)> = self
            .state
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

    pub fn validate_signed_vote(&self, signed_vote: &Vote<T>) -> Result<()> {
        signed_vote.validate_signature()?;
        self.validate_vote(&signed_vote.vote)?;
        self.validate_is_elder(signed_vote.voter)?;
        self.validate_vote_supersedes_existing_vote(signed_vote)?;
        self.validate_voters_have_not_changed_proposals(signed_vote)?;
        Ok(())
    }

    fn validate_vote(&self, vote: &UnsignedVote<T>) -> Result<()> {
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
                    &votes.iter().flat_map(Vote::unpack_votes).cloned().collect(),
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
}
