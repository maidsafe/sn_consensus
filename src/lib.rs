pub mod consensus;
pub mod decision;
pub mod fault;
pub mod mvba;
pub mod sn_handover;
pub mod sn_membership;
pub mod vote;
pub mod vote_count;

#[cfg(feature = "bad_crypto")]
pub mod bad_crypto;
// #[cfg(feature = "blsttc")]
// pub mod blsttc;
#[cfg(feature = "ed25519")]
pub mod ed25519;

use blsttc::{PublicKeySet, PublicKey, SignatureShare, Signature};
use serde::Serialize;

pub use crate::consensus::{Consensus, VoteResponse};
pub use crate::decision::Decision;
pub use crate::fault::{Fault, FaultError};
pub use crate::sn_handover::{Handover, UniqueSectionId};
pub use crate::sn_membership::{Generation, Membership, Reconfig};
pub use crate::vote::{Ballot, Proposition, SignedVote, Vote};
pub use crate::vote_count::{Candidate, VoteCount};

// #[cfg(feature = "bad_crypto")]
// pub use crate::bad_crypto::{PublicKey, SecretKey, Signature};
// #[cfg(feature = "blsttc")]
// pub use crate::blsttc::{PublicKey, SecretKey, Signature};
// #[cfg(feature = "ed25519")]
// pub use crate::ed25519::{PublicKey, SecretKey, Signature};

pub mod error;
pub use crate::error::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub type NodeId = u8;

pub fn verify_sig_share<M: Serialize>(
    msg: &M,
    sig: &SignatureShare,
    voter: NodeId,
    voters: &PublicKeySet,
) -> Result<()> {
    let public_key = voters.public_key_share(voter as u64);
    let msg_bytes = bincode::serialize(msg)?;
    if public_key.verify(sig, msg_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidElderSignature)
    }
}

pub fn verify_sig<M: Serialize>(
    msg: &M,
    sig: &Signature,
    public_key: &PublicKey,
) -> Result<()> {
    let msg_bytes = bincode::serialize(msg)?;
    if public_key.verify(sig, msg_bytes) {
        Ok(())
    } else {
        Err(Error::InvalidElderSignature)
    }
}
