use blsttc::{PublicKeySet, Signature};

use self::tag::{Domain, Tag};

pub mod consensus;
pub mod error;
pub mod hash;
pub mod tag;

mod abba;
mod broadcaster;
mod bundle;
// TODO: remove me
#[allow(clippy::module_inception)]
mod mvba;
mod vcbc;

pub type NodeId = usize;

/// A proposed data. It is the same as $w$ in the spec.
pub type Proposal = Vec<u8>;

/// A proof if decided proposed data. It is the same as $π$ in the spec.
#[derive(Debug)]
pub struct Proof {
    pub domain: Domain,
    pub proposer: NodeId,
    pub abba_signature: Signature,
    pub abba_round: usize,
    pub vcbc_signature: Signature,
}

impl Proof {
    pub fn verify(
        &self,
        proposal: &Proposal,
        pks: &PublicKeySet,
    ) -> Result<bool, crate::mvba::error::Error> {
        let tag = Tag::new(self.domain.clone(), self.proposer);

        if vcbc::verify_delivered_proposal(&tag, proposal, &self.vcbc_signature, pks)? {
            Ok(abba::verify_decided_proposal(
                &tag,
                &self.abba_signature,
                self.abba_round,
                pks,
            )?)
        } else {
            Ok(false)
        }
    }
}

/// MessageValidity is same as &Q_{ID}$ ins spec: a global polynomial-time computable
/// predicate QID known to all parties, which is determined by an external application.
/// Each party may propose a value v together with a proof π that should satisfy QID .
pub type MessageValidity = fn(NodeId, &Proposal) -> bool;
