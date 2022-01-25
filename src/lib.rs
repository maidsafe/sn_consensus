pub mod consensus;
pub mod membership;
pub mod proposal;
pub mod vote;

#[cfg(feature = "bad_crypto")]
pub mod bad_crypto;
// #[cfg(feature = "blsttc")]
// pub mod blsttc;
#[cfg(feature = "ed25519")]
pub mod ed25519;

// #[cfg(feature = "bad_crypto")]
// pub use crate::bad_crypto::{PublicKey, SecretKey, Signature};
// #[cfg(feature = "blsttc")]
// pub use crate::blsttc::{PublicKey, SecretKey, Signature};
// #[cfg(feature = "ed25519")]
// pub use crate::ed25519::{PublicKey, SecretKey, Signature};

pub use blsttc::{PublicKeyShare, SecretKeyShare, SignatureShare};

pub use crate::consensus::State;
pub use crate::membership::{Generation, MembershipState, Reconfig};
pub use crate::proposal::Proposal;
pub use crate::vote::{Ballot, Proposition, UnsignedVote, Vote};

pub mod error;
pub use crate::error::Error;
pub type Result<T> = std::result::Result<T, Error>;
