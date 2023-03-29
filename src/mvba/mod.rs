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
    pub proposer: NodeId,
    pub abba_signature: Signature,
    pub abba_round: usize,
    pub vcbc_signature: Signature,
}

impl Proof {
    fn validate<P: Serialize>(
        &self,
        domain: Domain,
        proposal: &P,
        pk: &PublicKey,
    ) -> Result<bool, crate::mvba::error::Error> {
        let tag = Tag::new(domain, self.proposer);

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
    pub domain: Domain,
    pub proposal: P,
    pub proof: Proof,
}

impl<P: Serialize> Decision<P> {
    pub fn validate(&self, pk: &PublicKey) -> Result<bool, crate::mvba::error::Error> {
        self.proof.validate(self.domain.clone(), &self.proposal, pk)
    }
}

use blsttc::SecretKey;

pub fn mock_decision<P: Clone + Serialize>(
    domain: Domain,
    proposal: P,
    proposer: NodeId,
    sk: &SecretKey,
) -> Result<Decision<P>, error::Error> {
    use self::hash::Hash32;
    use crate::mvba::abba::message::MainVoteValue;

    let abba_round = 0;
    let tag = Tag::new(domain.clone(), proposer);
    let d = Hash32::calculate(proposal.clone())?;
    let vcbc_sign_bytes = vcbc::c_ready_bytes_to_sign(&tag, &d)?;
    let abba_sign_bytes =
        abba::main_vote_bytes_to_sign(&tag, abba_round, &MainVoteValue::Value(true))?;

    let vcbc_signature = sk.sign(vcbc_sign_bytes);
    let abba_signature = sk.sign(abba_sign_bytes);

    Ok(Decision {
        domain,
        proposal,
        proof: Proof {
            proposer,
            abba_signature,
            abba_round,
            vcbc_signature,
        },
    })
}

#[cfg(test)]
mod tests {
    use blsttc::SecretKey;

    use super::{mock_decision, tag::Domain};

    #[test]
    fn test_mocked_decision() {
        let sk = SecretKey::random();
        let domain = Domain::new("test-domain", 0);
        let mocked_decision = mock_decision(domain, "test", 0, &sk).unwrap();
        assert!(mocked_decision.validate(&sk.public_key()).unwrap());
    }
}
