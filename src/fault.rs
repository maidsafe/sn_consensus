use blsttc::PublicKeySet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{NodeId, Proposition, SignedVote};

#[derive(Debug, Error)]
pub enum FaultError {
    #[error("The claimed ChangedVote fault is dealing with votes from different voters")]
    ChangedVoteFaultIsFromDifferentVoters,
    #[error("The claimed ChangedVote fault is not actually incompatible votes")]
    ChangedVoteIsNotActuallyChanged,
    #[error("FaultProof used a vote that was improperly signed")]
    AccusedAnImproperlySignedVote,
    #[error("InvalidFaultProof was actually valid")]
    AccusedVoteOfInvalidFaultButAllFaultsAreValid,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Fault<T: Proposition> {
    ChangedVote { a: SignedVote<T>, b: SignedVote<T> },
    InvalidFault { signed_vote: SignedVote<T> },
}

impl<T: Proposition> Fault<T> {
    pub fn voter_at_fault(&self) -> NodeId {
        match self {
            Fault::ChangedVote { a, .. } => a.voter,
            Fault::InvalidFault { signed_vote } => signed_vote.voter,
        }
    }

    pub fn validate(&self, voters: &PublicKeySet) -> std::result::Result<(), FaultError> {
        match self {
            Self::ChangedVote { a, b } => {
                a.validate_signature(voters)
                    .map_err(|_| FaultError::AccusedAnImproperlySignedVote)?;
                b.validate_signature(voters)
                    .map_err(|_| FaultError::AccusedAnImproperlySignedVote)?;
                if a.voter != b.voter {
                    return Err(FaultError::ChangedVoteFaultIsFromDifferentVoters);
                }
                if a.supersedes(b) || b.supersedes(a) {
                    return Err(FaultError::ChangedVoteIsNotActuallyChanged);
                }
                Ok(())
            }
            Self::InvalidFault { signed_vote } => {
                signed_vote
                    .validate_signature(voters)
                    .map_err(|_| FaultError::AccusedAnImproperlySignedVote)?;

                let all_faults_are_valid = signed_vote
                    .vote
                    .faults
                    .iter()
                    .all(|f| f.validate(voters).is_ok());

                if signed_vote.vote.faults.is_empty() || all_faults_are_valid {
                    Err(FaultError::AccusedVoteOfInvalidFaultButAllFaultsAreValid)
                } else {
                    Ok(())
                }
            }
        }
    }
}
