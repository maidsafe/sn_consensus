use blsttc::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

use self::tag::{Domain, Tag};

pub mod bundle;
pub mod consensus;
pub mod error;
pub mod hash;
pub mod tag;

mod abba;
mod broadcaster;
// TODO: remove me
#[allow(clippy::module_inception)]
mod mvba;
mod vcbc;

pub type NodeId = usize;

/// A proof for the decided proposed data.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Proof {
    pub domain: Domain,
    pub proposer: NodeId,
    pub abba_signature: Signature,
    pub abba_round: usize,
    pub vcbc_signature: Signature,
}

impl Proof {
    fn validate<P: Serialize>(
        &self,
        proposal: &P,
        pk: &PublicKey,
    ) -> Result<bool, crate::mvba::error::Error> {
        let tag = Tag::new(self.domain.clone(), self.proposer);

        if vcbc::verify_delivered_proposal(&tag, proposal, &self.vcbc_signature, pk)? {
            Ok(abba::verify_decided_proposal(
                &tag,
                &self.abba_signature,
                self.abba_round,
                pk,
            )?)
        } else {
            Ok(false)
        }
    }
}

/// MessageValidity is same as &Q_{ID}$ ins spec: a global polynomial-time computable
/// predicate QID known to all parties, which is determined by an external application.
/// Each party may propose a value v together with a proof π that should satisfy QID .
pub type MessageValidity<P> = fn(NodeId, &P) -> bool;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Decision<P> {
    pub proposal: P,
    pub proof: Proof,
}

impl<P: Serialize> Decision<P> {
    pub fn validate(&self, pk: &PublicKey) -> Result<bool, crate::mvba::error::Error> {
        self.proof.validate(&self.proposal, pk)
    }
}
