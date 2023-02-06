pub(crate) mod error;
mod message;

use self::message::{Message, Vote};

use self::{error::Error, error::Result};
use super::tag::Domain;
use super::vcbc;
use super::{hash::Hash32, Proposal};
use crate::mvba::tag::Tag;
use crate::mvba::{broadcaster::Broadcaster, NodeId};
use blsttc::{PublicKeySet, SecretKeyShare, Signature};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub(crate) const MODULE_NAME: &str = "mvba";

pub struct Mvba {
    domain: Domain,  // this is same as $ID.s$ in spec
    i: NodeId,       // this is same as $i$ in spec
    l: usize,        // this is same as $a$ in spec
    v: Option<bool>, // this is same as $v$ in spec
    proposals: HashMap<NodeId, (Proposal, Signature)>,
    votes_per_proposer: HashMap<NodeId, HashMap<NodeId, Vote>>,
    voted: bool,
    pub_key_set: PublicKeySet,
    sec_key_share: SecretKeyShare,
    parties: Vec<NodeId>,
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl Mvba {
    pub fn new(
        domain: Domain,
        self_id: NodeId,
        sec_key_share: SecretKeyShare,
        pub_key_set: PublicKeySet,
        parties: Vec<NodeId>,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            domain,
            i: self_id,
            l: 0,
            v: None,
            voted: false,
            proposals: HashMap::new(),
            votes_per_proposer: HashMap::new(),
            pub_key_set,
            sec_key_share,
            parties,
            broadcaster,
        }
    }

    pub fn set_proposal(
        &mut self,
        proposer: NodeId,
        proposal: Proposal,
        signature: Signature,
    ) -> Result<()> {
        debug_assert!(self.parties.contains(&proposer));
        let tag = self.build_tag(proposer);
        let digest = Hash32::calculate(&proposal);
        let sign_bytes = vcbc::c_ready_bytes_to_sign(&tag, &digest)?;
        if !self.pub_key_set.public_key().verify(&signature, sign_bytes) {
            return Err(Error::InvalidMessage(
                "proposal with an invalid proof".to_string(),
            ));
        }

        self.proposals.insert(proposer, (proposal, signature));
        self.vote()
    }

    pub fn move_to_next_proposal(&mut self) -> Result<bool> {
        log::debug!(
            "party {} moves to the next proposer: {}",
            self.i,
            self.current_proposer()?
        );
        if self.l + 1 == self.parties.len() {
            // no more proposal
            return Ok(false);
        }
        self.l += 1;
        self.v = None;
        self.voted = false;

        self.vote()?;
        Ok(true)
    }

    pub fn current_tag(&self) -> Result<Tag> {
        Ok(self.build_tag(self.current_proposer()?))
    }

    pub fn build_tag(&self, proposer: NodeId) -> Tag {
        Tag::new(self.domain.clone(), proposer)
    }

    pub fn current_proposer(&self) -> Result<NodeId> {
        match self.parties.get(self.l) {
            Some(p) => Ok(*p),
            None => Err(Error::Generic("parties is not initialized".to_string())),
        }
    }

    pub fn completed_vote(&self) -> Option<bool> {
        self.v
    }

    pub fn completed_vote_value(&self) -> Result<Option<&(Proposal, Signature)>> {
        Ok(self.proposals.get(&self.current_proposer()?))
    }

    fn check_message(&mut self, msg: &Message) -> Result<()> {
        if msg.vote.tag.domain != self.domain {
            return Err(Error::InvalidMessage(format!(
                "invalid domain. expected: {}, got {}",
                self.domain, msg.vote.tag.domain
            )));
        }

        let sign_bytes = bincode::serialize(&msg.vote)?;
        if !self
            .pub_key_set
            .public_key_share(msg.voter)
            .verify(&msg.signature, sign_bytes)
        {
            return Err(Error::InvalidMessage("invalid signature".to_string()));
        }

        if !msg.vote.value && msg.vote.proof.is_some() {
            return Err(Error::InvalidMessage("no vote with proof".to_string()));
        }

        if msg.vote.value && msg.vote.proof.is_none() {
            return Err(Error::InvalidMessage("yes vote without proof".to_string()));
        }

        if let Some((digest, signature)) = &msg.vote.proof {
            let sign_bytes = vcbc::c_ready_bytes_to_sign(&msg.vote.tag, digest)
                .map_err(|e| Error::Generic(e.to_string()))?;
            if !self.pub_key_set.public_key().verify(signature, sign_bytes) {
                return Err(Error::InvalidMessage(
                    "proposal with an invalid proof".to_string(),
                ));
            }
        };

        Ok(())
    }

    pub fn add_vote(&mut self, msg: &Message) -> Result<bool> {
        let votes = self.must_get_proposer_votes(&msg.vote.tag.proposer)?;
        if let Some(exist) = votes.get(&msg.voter) {
            if exist != &msg.vote {
                return Err(Error::InvalidMessage(format!(
                    "double vote detected from {:?}",
                    msg.voter
                )));
            }
            return Ok(false);
        }

        votes.insert(msg.voter, msg.vote.clone());

        if msg.vote.value && !self.proposals.contains_key(&msg.vote.tag.proposer) {
            // If a v-vote from Pj indicates 1 but Pi has not yet received Pa ’s proposal,
            // ignore the vote and ask Pj to supply Pa ’s proposal
            // (by sending it the message (ID|vcbc.a.0, c-request)).

            log::debug!(
                "party {} requests proposal from {}",
                self.i,
                msg.vote.tag.proposer,
            );
            let data = vcbc::make_c_request_message(self.current_tag()?)?;

            self.broadcaster.borrow_mut().send_to(
                vcbc::MODULE_NAME,
                Some(msg.vote.tag.proposer),
                data,
                msg.voter,
            );

            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// receive_message process the received message 'msg`
    pub fn receive_message(&mut self, msg: Message) -> Result<()> {
        log::trace!("party {} received message: {:?}", self.i, msg);

        self.check_message(&msg)?;
        if !self.add_vote(&msg)? {
            return Ok(());
        }

        // wait for n − t messages (v-echo, wj , πj ) to be c-delivered with tag ID|vcbc.j.0
        //from distinct Pj such that QID (wj , πj ) holds
        let threshold = self.threshold();
        if self.proposals.len() >= threshold && self.v.is_none() {
            // wait for n − t messages (ID, v-vote, a, uj , ρj ) from distinct Pj such
            // that VID|a (uj , ρj) holds
            let votes = self.must_get_proposer_votes(&msg.vote.tag.proposer)?;
            if votes.len() >= threshold {
                if votes.values().any(|v| v.value) {
                    log::debug!(
                        "party {} completed for proposer {}.",
                        self.i,
                        self.current_proposer()?
                    );
                    // if there is some uj = 1 then
                    // v ← 1; ρ ← ρj
                    self.v = Some(true);
                } else {
                    // else
                    // v ← 0; ρ ← ⊥
                    self.v = Some(false);
                }
            }
        }

        Ok(())
    }

    fn proposer_votes_mut(&mut self, proposer: &NodeId) -> Result<&mut HashMap<NodeId, Vote>> {
        if !self.votes_per_proposer.contains_key(proposer) {
            self.votes_per_proposer.insert(*proposer, HashMap::new());
        }
        match self.votes_per_proposer.get_mut(proposer) {
            Some(v) => Ok(v),
            None => Err(Error::Generic(
                "votes_per_proposer is not initialized".to_string(),
            )),
        }
    }

    fn vote(&mut self) -> Result<()> {
        // wait for n − t messages (v-echo, wj , πj ) to be c-delivered with tag ID|vcbc.j.0
        //from distinct Pj such that QID (wj , πj ) holds
        if self.proposals.len() >= self.threshold() && !self.voted {
            let tag = self.current_tag()?;
            let vote = match self.proposals.get(&tag.proposer) {
                None => {
                    // if wa = ⊥ then
                    // send the message (ID, v-vote, a, 0, ⊥) to all parties
                    Vote {
                        tag,
                        value: false,
                        proof: None,
                    }
                }
                Some((proposal, signature)) => {
                    // else
                    // let ρ be the message that completes the c-broadcast with tag ID|vcbc.a.0
                    // send the message (ID, v-vote, a, 1, ρ) to all parties
                    let digest = Hash32::calculate(proposal);
                    Vote {
                        tag,
                        value: true,
                        proof: Some((digest, signature.clone())),
                    }
                }
            };

            self.broadcast(vote)?;
            self.voted = true;
        }

        Ok(())
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, vote: Vote) -> Result<()> {
        log::debug!("party {} broadcasts {vote:?}", self.i);

        let sign_bytes = bincode::serialize(&vote)?;
        let sig = self.sec_key_share.sign(sign_bytes);
        let msg = Message {
            vote,
            voter: self.i,
            signature: sig,
        };
        let data = bincode::serialize(&msg)?;
        self.broadcaster
            .borrow_mut()
            .broadcast(MODULE_NAME, None, data);
        self.receive_message(msg)?;
        Ok(())
    }

    // threshold return the threshold of the public key set.
    // It SHOULD be `n-t` according to the spec
    fn threshold(&self) -> usize {
        self.pub_key_set.threshold() + 1
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
