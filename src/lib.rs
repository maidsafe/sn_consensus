pub mod consensus;
pub mod sn_handover;
pub mod sn_membership;
pub mod vote;

#[cfg(feature = "bad_crypto")]
pub mod bad_crypto;
// #[cfg(feature = "blsttc")]
// pub mod blsttc;
#[cfg(feature = "ed25519")]
pub mod ed25519;

pub use crate::consensus::Consensus;
pub use crate::sn_handover::{UniqueSectionId, Handover};
pub use crate::sn_membership::{Generation, Membership, Reconfig};
pub use crate::vote::{Ballot, Proposition, SignedVote, Vote};

// #[cfg(feature = "bad_crypto")]
// pub use crate::bad_crypto::{PublicKey, SecretKey, Signature};
// #[cfg(feature = "blsttc")]
// pub use crate::blsttc::{PublicKey, SecretKey, Signature};
// #[cfg(feature = "ed25519")]
// pub use crate::ed25519::{PublicKey, SecretKey, Signature};

pub mod error;
pub use crate::error::Error;
pub type Result<T> = std::result::Result<T, Error>;
