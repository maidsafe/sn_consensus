pub(crate) mod error;
mod message;

use self::message::{Message, Vote};

use self::{error::Error, error::Result};
use super::vcbc;
use super::{hash::Hash32, Proposal};
use crate::mvba::{broadcaster::Broadcaster, NodeId};
use blsttc::{PublicKeySet, SecretKeyShare, Signature};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub(crate) const MODULE_NAME: &str = "mvba";

pub struct Mvba {
    id: String,      // this is same as $ID$ in spec
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
        id: String,
        self_id: NodeId,
        sec_key_share: SecretKeyShare,
        pub_key_set: PublicKeySet,
        parties: Vec<NodeId>,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            id,
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

        let digest = Hash32::calculate(&proposal);
        let sign_bytes = vcbc::c_ready_bytes_to_sign(&self.id, &proposer, &digest).unwrap();
        if !self.pub_key_set.public_key().verify(&signature, sign_bytes) {
            return Err(Error::InvalidMessage(
                "proposal with an invalid proof".to_string(),
            ));
        }

        self.proposals.insert(proposer, (proposal, signature));
        self.vote()
    }

    pub fn move_to_next_proposal(&mut self) -> Result<()> {
        self.l += 1;
        self.v = None;
        self.voted = false;

        self.vote()
    }

    pub fn is_completed(&self) -> bool {
        self.v.is_some()
    }

    pub fn completed_vote(&self) -> bool {
        self.v.unwrap()
    }

    pub fn completed_vote_one(&self) -> (Proposal, Signature) {
        self.proposals.get(&self.l).unwrap().clone()
    }

    fn check_message(&mut self, msg: &Message) -> Result<()> {
        if msg.vote.id != self.id {
            return Err(Error::InvalidMessage(format!(
                "invalid ID. expected: {}, got {}",
                self.id, msg.vote.id
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

        if let Some((proposal, signature)) = &msg.vote.proof {
            let digest = Hash32::calculate(proposal);
            let sign_bytes = vcbc::c_ready_bytes_to_sign(&self.id, &self.l, &digest).unwrap();
            if !self.pub_key_set.public_key().verify(signature, sign_bytes) {
                return Err(Error::InvalidMessage(
                    "proposal with an invalid proof".to_string(),
                ));
            }
        };

        Ok(())
    }

    pub fn add_vote(&mut self, msg: &Message) -> Result<bool> {
        let votes = self.must_get_proposer_votes(&msg.vote.proposer);
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

        // set the proposal if we don't have it
        if let std::collections::hash_map::Entry::Vacant(e) =
            self.proposals.entry(msg.vote.proposer)
        {
            if let Some((proposal, signature)) = &msg.vote.proof {
                e.insert((proposal.clone(), signature.clone()));
            }
        }

        Ok(true)
    }

    /// receive_message process the received message 'msg` from `sender`
    pub fn receive_message(&mut self, msg: Message) -> Result<()> {
        self.check_message(&msg)?;
        if !self.add_vote(&msg)? {
            return Ok(());
        }

        // Message is for another proposal, not current one
        // TODO: test me!
        if msg.vote.proposer != self.l {
            return Ok(());
        }

        // wait for n − t messages (v-echo, wj , πj ) to be c-delivered with tag ID|vcbc.j.0
        //from distinct Pj such that QID (wj , πj ) holds
        if self.proposals.len() >= self.threshold() {
            // wait for n − t messages (ID, v-vote, a, uj , ρj ) from distinct Pj such
            // that VID|a (uj , ρj) holds
            let votes = self.must_get_proposer_votes(&msg.vote.proposer);
            if votes.len() >= self.threshold() {
                let votes = self.must_get_proposer_votes(&msg.vote.proposer);
                let mut yes_votes = votes.values().filter(|v| v.value);
                match yes_votes.next() {
                    // if there is some uj = 1 then
                    Some(_) => {
                        // v ← 1; ρ ← ρj
                        self.v = Some(true);
                    }
                    // else
                    None => {
                        // v ← 0; ρ ← ⊥
                        self.v = Some(false);
                    }
                }
            }
        }

        Ok(())
    }

    // TODO: make me better, no unwrap?
    fn must_get_proposer_votes(&mut self, proposer: &NodeId) -> &mut HashMap<NodeId, Vote> {
        if !self.votes_per_proposer.contains_key(proposer) {
            self.votes_per_proposer.insert(*proposer, HashMap::new());
        }
        self.votes_per_proposer.get_mut(proposer).unwrap()
    }
    fn vote(&mut self) -> Result<()> {
        // wait for n − t messages (v-echo, wj , πj ) to be c-delivered with tag ID|vcbc.j.0
        //from distinct Pj such that QID (wj , πj ) holds
        if self.proposals.len() >= self.threshold() && !self.voted {
            let a = self.parties.get(self.l).unwrap();
            let vote = match self.proposals.get(a) {
                None => {
                    // if wa = ⊥ then
                    // send the message (ID, v-vote, a, 0, ⊥) to all parties
                    Vote {
                        id: self.id.clone(),
                        proposer: *a,
                        value: false,
                        proof: None,
                    }
                }
                Some((proposal, signature)) => {
                    // else
                    // let ρ be the message that completes the c-broadcast with tag ID|vcbc.a.0
                    // send the message (ID, v-vote, a, 1, ρ) to all parties
                    Vote {
                        id: self.id.clone(),
                        proposer: *a,
                        value: true,
                        proof: Some((proposal.clone(), signature.clone())),
                    }
                }
            };

            self.broadcast(vote)?;
        }

        Ok(())
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, vote: Vote) -> Result<()> {
        let sign_bytes = bincode::serialize(&vote)?;
        let sig = self.sec_key_share.sign(sign_bytes);
        let msg = Message {
            vote,
            voter: self.i,
            signature: sig,
        };
        let data = bincode::serialize(&msg)?;
        self.broadcaster.borrow_mut().broadcast(MODULE_NAME, data);
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
