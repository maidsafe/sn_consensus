use blsttc::PublicKeyShare;
use core::fmt::Debug;
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{Ballot, Generation, Reconfig, SignedVote};

#[derive(Error, Debug)]
pub enum Error {
    #[error("We experienced an IO error")]
    IO(#[from] std::io::Error),
    #[error("The operation requested assumes we have at least one member")]
    NoMembers,
    #[error("Packet was not destined for this actor: {dest:?} != {actor:?}")]
    WrongDestination {
        dest: PublicKeyShare,
        actor: PublicKeyShare,
    },
    #[error(
        "We can not accept any new join requests, network member size is at capacity: {members:?}"
    )]
    MembersAtCapacity { members: BTreeSet<u8> },
    #[error(
        "An existing member `{requester:?}` can not request to join again. (members: {members:?})"
    )]
    JoinRequestForExistingMember {
        requester: u8,
        members: BTreeSet<u8>,
    },
    #[error("You must be a member to request to leave ({requester:?} not in {members:?})")]
    LeaveRequestForNonMember {
        requester: u8,
        members: BTreeSet<u8>,
    },
    #[error("A merged vote must be from the same generation as the child vote: {child_gen} != {merge_gen}")]
    MergedVotesMustBeFromSameGen {
        child_gen: Generation,
        merge_gen: Generation,
    },
    #[error("A vote is always for the next generation: vote gen {vote_gen} != {gen} + 1, pending gen: {pending_gen}")]
    VoteNotForNextGeneration {
        vote_gen: Generation,
        gen: Generation,
        pending_gen: Generation,
    },
    #[error("({public_key:?} is not in {elders:?})")]
    NotElder {
        public_key: PublicKeyShare,
        elders: BTreeSet<PublicKeyShare>,
    },
    #[error("Voter changed their mind: {reconfigs:?}")]
    VoterChangedMind {
        reconfigs: BTreeSet<(PublicKeyShare, Reconfig)>,
    },
    #[error("Existing vote {existing_vote:?} not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote { existing_vote: SignedVote },
    #[error("The super majority ballot does not actually have supermajority: {ballot:?} (elders: {elders:?})")]
    SuperMajorityBallotIsNotSuperMajority {
        ballot: Ballot,
        elders: BTreeSet<PublicKeyShare>,
    },
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote {0:?}")]
    InvalidVoteInHistory(SignedVote),
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),
    #[error("Elder signature is not valid")]
    InvalidElderSignature,

    #[cfg(feature = "ed25519")]
    #[error("Ed25519 Error {0}")]
    Ed25519(#[from] crate::ed25519::Error),

    #[cfg(feature = "blsttc")]
    #[error("Blsttc Error {0}")]
    Blsttc(#[from] crate::blsttc::Error),

    #[cfg(feature = "bad_crypto")]
    #[error("Failed Signature Verification")]
    BadCrypto(#[from] crate::bad_crypto::Error),
}
