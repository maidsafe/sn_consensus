use std::collections::{BTreeMap, BTreeSet};

use blsttc::{PublicKeyShare, SecretKeyShare};
use log::info;
use rand::{CryptoRng, Rng};

use crate::sn_membership::Generation;
use crate::vote::{Ballot, Proposition, SignedVote, Vote};
use crate::{Error, Result};

#[derive(Debug)]
pub struct Consensus<T: Proposition> {
    pub elders: BTreeSet<PublicKeyShare>,
    pub secret_key: SecretKeyShare,
    pub votes: BTreeMap<PublicKeyShare, SignedVote<T>>,
}

impl<T: Proposition> Consensus<T> {
    pub fn from(secret_key: SecretKeyShare, elders: BTreeSet<PublicKeyShare>) -> Self {
        Consensus::<T> {
            secret_key,
            elders,
            votes: Default::default(),
        }
    }

    pub fn random(mut rng: impl Rng + CryptoRng) -> Self {
        Consensus::<T> {
            secret_key: rng.gen(),
            elders: Default::default(),
            votes: Default::default(),
        }
    }

    pub fn public_key_share(&self) -> PublicKeyShare {
        self.secret_key.public_key_share()
    }

    // handover: gen = gen
    // membership: gen = pending_gen
    /// Handles a signed vote
    /// Returns the vote we cast and the reached consensus vote in case consensus was reached
    pub fn handle_signed_vote(
        &mut self,
        signed_vote: SignedVote<T>,
        gen: Generation,
    ) -> Result<(Option<SignedVote<T>>, Option<SignedVote<T>>)> {
        self.log_signed_vote(&signed_vote);

        if self.is_split_vote(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected split vote");
            let merge_vote = Vote {
                gen: gen,
                ballot: Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            if let Some(our_vote) = self.votes.get(&self.public_key_share()) {
                let proposals_we_voted_for =
                    BTreeSet::from_iter(our_vote.proposals().into_iter().map(|(_, r)| r));
                let proposals_we_would_vote_for: BTreeSet<_> = signed_merge_vote
                    .proposals()
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect();

                if proposals_we_voted_for == proposals_we_would_vote_for {
                    info!("[MBR] This vote didn't add new information, waiting for more votes...");
                    return Ok((None, None));
                }
            }

            info!("[MBR] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return Ok((Some(self.cast_vote(signed_merge_vote)), None));
        }

        if self.is_super_majority_over_super_majorities(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected super majority over super majorities");
            assert!(self.elders.contains(&self.public_key_share()));
            // store a proof of what the network decided in our history so that we can onboard future procs.
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();

            let vote = Vote {
                gen,
                ballot,
            };
            let signed_vote = self.sign_vote(vote)?;

            // clear our pending votes
            self.votes = Default::default();

            // return obtained super majority over super majority (aka consensus)
            return Ok((None, Some(signed_vote)));
        }

        if self.is_super_majority(&self.votes.values().cloned().collect())? {
            info!("[MBR] Detected super majority");

            if let Some(our_vote) = self.votes.get(&self.public_key_share()) {
                // We voted during this generation.

                if our_vote.vote.is_super_majority_ballot() {
                    info!("[MBR] We've already sent a super majority, waiting till we either have a split vote or SM / SM");
                    return Ok((None, None));
                }
            }

            info!("[MBR] broadcasting super majority");
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();
            let vote = Vote {
                gen,
                ballot,
            };
            let signed_vote = self.sign_vote(vote)?;
            return Ok((Some(self.cast_vote(signed_vote)), None));
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.public_key_share()) {
            let signed_vote = self.sign_vote(Vote {
                gen,
                ballot: signed_vote.vote.ballot,
            })?;
            return Ok((Some(self.cast_vote(signed_vote)), None));
        }

        Ok((None, None))
    }

    pub fn sign_vote(&self, vote: Vote<T>) -> Result<SignedVote<T>> {
        Ok(SignedVote {
            voter: self.public_key_share(),
            sig: self.secret_key.sign(&vote.to_bytes()?),
            vote,
        })
    }

    pub fn cast_vote(&mut self, signed_vote: SignedVote<T>) -> SignedVote<T> {
        self.log_signed_vote(&signed_vote);
        signed_vote
    }

    pub fn log_signed_vote(&mut self, signed_vote: &SignedVote<T>) {
        for vote in signed_vote.unpack_votes() {
            let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
            if vote.supersedes(existing_vote) {
                *existing_vote = vote.clone()
            }
        }
    }

    pub fn count_votes(
        &self,
        votes: &BTreeSet<SignedVote<T>>,
    ) -> BTreeMap<BTreeSet<T>, usize> {
        let mut count: BTreeMap<BTreeSet<T>, usize> = Default::default();

        for vote in votes.iter() {
            let proposals =
                BTreeSet::from_iter(vote.proposals().into_iter().map(|(_, prop)| prop));
            let c = count.entry(proposals).or_default();
            *c += 1;
        }

        count
    }

    fn is_split_vote(&self, votes: &BTreeSet<SignedVote<T>>) -> Result<bool> {
        let counts = self.count_votes(votes);
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let voters = BTreeSet::from_iter(votes.iter().map(|v| v.voter));
        let remaining_voters = self.elders.difference(&voters).count();

        // give the remaining votes to the proposals with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        Ok(
            3 * voters.len() > 2 * self.elders.len()
                && 3 * predicted_votes <= 2 * self.elders.len(),
        )
    }

    pub fn is_super_majority(&self, votes: &BTreeSet<SignedVote<T>>) -> Result<bool> {
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

        Ok(3 * count_of_agreeing_super_majorities > 2 * self.elders.len())
    }

    pub fn validate_is_elder(&self, public_key: PublicKeyShare) -> Result<()> {
        if !self.elders.contains(&public_key) {
            Err(Error::NotElder {
                public_key,
                elders: self.elders.clone(),
            })
        } else {
            Ok(())
        }
    }

    pub fn validate_vote_supersedes_existing_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        if self.votes.contains_key(&signed_vote.voter)
            && !signed_vote.supersedes(&self.votes[&signed_vote.voter])
            && !self.votes[&signed_vote.voter].supersedes(signed_vote)
        {
            Err(Error::ExistingVoteIncompatibleWithNewVote)
        } else {
            Ok(())
        }
    }

    pub fn validate_voters_have_not_changed_proposals(
        &self,
        signed_vote: &SignedVote<T>,
    ) -> Result<()> {
        // Ensure that nobody is trying to change their Proposal proposals.
        let proposals: BTreeSet<(PublicKeyShare, T)> = self
            .votes
            .values()
            .flat_map(|v| v.proposals())
            .chain(signed_vote.proposals())
            .collect();

        let voters = BTreeSet::from_iter(proposals.iter().map(|(actor, _)| actor));
        if voters.len() != proposals.len() {
            Err(Error::VoterChangedVote)
        } else {
            Ok(())
        }
    }
}
