use core::fmt::Debug;
use thiserror::Error;

use crate::{Generation, UniqueSectionId};

#[derive(Error, Debug)]
pub enum Error {
    #[error("We experienced an IO error")]
    IO(#[from] std::io::Error),
    #[error("The operation requested assumes we have at least one member")]
    NoMembers,
    #[error("We can not accept any new join requests, network member size is at capacity")]
    MembersAtCapacity,
    #[error("An existing member can not request to join again")]
    JoinRequestForExistingMember,
    #[error("You must be a member to request to leave")]
    LeaveRequestForNonMember,
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
    #[error("Vote received has a different unique section id: vote gen {vote_gen} != {gen}")]
    VoteWithInvalidUniqueSectionId {
        vote_gen: UniqueSectionId,
        gen: UniqueSectionId,
    },
    #[error("The voter is not an elder")]
    NotElder,
    #[error("Voter changed their vote")]
    VoterChangedVote,
    #[error("Existing vote not compatible with new vote")]
    ExistingVoteIncompatibleWithNewVote,
    #[error("The super majority ballot does not actually have supermajority")]
    SuperMajorityBallotIsNotSuperMajority,
    #[error("Invalid generation {0}")]
    InvalidGeneration(Generation),
    #[error("History contains an invalid vote")]
    InvalidVoteInHistory,
    #[error("Failed to encode with bincode")]
    Encoding(#[from] bincode::Error),
    #[error("Elder signature is not valid")]
    InvalidElderSignature,
    #[error("SuperMajority signed a different set of proposals than the proposals in the vote")]
    SuperMajorityProposalsDoesNotMatchVoteProposals,
    #[error("Blsttc Error {0}")]
    Blsttc(#[from] blsttc::error::Error),
    #[error("Client attempted a faulty proposal")]
    AttemptedFaultyProposal,

    #[cfg(feature = "ed25519")]
    #[error("Ed25519 Error {0}")]
    Ed25519(#[from] crate::ed25519::Error),

    #[cfg(feature = "bad_crypto")]
    #[error("Failed Signature Verification")]
    BadCrypto(#[from] crate::bad_crypto::Error),
}
