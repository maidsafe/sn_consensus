pub(super) mod message;

mod error;
use blsttc::{PublicKeySet, PublicKeyShare, SecretKeyShare, Signature, SignatureShare};
use log::warn;

use self::error::{Error, Result};
use self::message::{Action, Message, PreVoteAction, PreVoteValue};
use super::NodeId;
use crate::mvba::abba::message::{MainVoteAction, MainVoteValue};
use crate::mvba::broadcaster::Broadcaster;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "abba";

/// The ABBA holds the information for Asynchronous Binary Byzantine Agreement protocol.
pub(crate) struct Abba {
    id: String, // this is same as $ID$ in spec
    i: NodeId,  // this is same as $i$ in spec
    vi: bool,   // this is same as $V_i$ in spec
    r: usize,   // this is same as $r$ in spec
    pub_key_set: PublicKeySet,
    sec_key_share: SecretKeyShare,
    broadcaster: Rc<RefCell<Broadcaster>>,
    round_pre_votes: Vec<HashMap<NodeId, PreVoteAction>>,
}

impl Abba {
    pub fn new(
        id: String,
        i: NodeId,
        vi: bool,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            id,
            i,
            vi,
            r: 1,
            pub_key_set,
            sec_key_share,
            broadcaster,
            round_pre_votes: Vec::new(),
        }
    }

    pub fn pre_vote(&mut self, value: PreVoteValue, justification: Signature) -> Result<()> {
        // Produce an S-signature share on the message: (ID, pre-vote, r, b).
        let sign_bytes = self.pre_vote_bytes_to_sign(&value)?;
        let sig_share = self.sec_key_share.sign(sign_bytes);
        let action = PreVoteAction {
            round: self.r,
            value,
            justification,
            sig_share,
        };
        let msg = Message {
            id: self.id.clone(),
            action: Action::PreVote(action),
        };
        // and send to all parties the message (ID, pre-process, Vi , signature share).
        self.broadcast(msg)
    }

    // receive_message process the received message 'msg` from `sender`
    pub fn receive_message(&mut self, sender: NodeId, msg: Message) -> Result<()> {
        log::debug!(
            "received {} message: {:?} from {}",
            msg.action_str(),
            msg,
            sender
        );

        self.check_message(&sender, &msg)?;
        self.add_message(&sender, &msg)?;

        match &msg.action {
            Action::PreVote(action) => {
                let pre_votes = self
                    .round_pre_votes
                    .get(action.round)
                    .expect("messages for this round is not set");

                if pre_votes.len() > self.threshold() {
                    // TODO:?????????????????????????????????
                    // Always all are one or zero!!!!!
                    let one_count = pre_votes
                        .iter()
                        .filter(|(_, a)| a.value == PreVoteValue::One)
                        .count();
                    let majority_votes: HashMap<&usize, &PreVoteAction> =
                        if one_count > self.threshold() {
                            pre_votes
                                .iter()
                                .filter(|(_, a)| a.value == PreVoteValue::One)
                                .collect()
                        } else {
                            pre_votes
                                .iter()
                                .filter(|(_, a)| a.value == PreVoteValue::Zero)
                                .collect()
                        };

                    let sig_share: HashMap<&&NodeId, &SignatureShare> = majority_votes
                        .iter()
                        .map(|(n, a)| (n, &a.sig_share))
                        .collect();
                    let sig = self.pub_key_set.combine_signatures(sig_share)?;

                    let v = MainVoteValue::One;
                    let sign_bytes = self.main_vote_bytes_to_sign(&v)?;
                    let sig_share = self.sec_key_share.sign(sign_bytes);

                    let main_vote_message = Message {
                        id: self.id.clone(),
                        action: Action::MainVote(MainVoteAction {
                            round: self.r,
                            value: v, // TODO: ???
                            justification: sig,
                            sig_share,
                        }),
                    };
                }
            }

            Action::MainVote(action) => {}
        }

        Ok(())
    }

    pub fn is_decided(&self) -> bool {
        todo!()
    }

    fn add_message(&mut self, sender: &NodeId, msg: &Message) -> Result<()> {
        match &msg.action {
            Action::PreVote(action) => {
                // make sure we have the round messages
                while self.round_pre_votes.len() < action.round {
                    self.round_pre_votes.push(HashMap::new());
                }
                // TODO, @D_Rusu, please how to not unwrap here?
                let pre_votes = self.round_pre_votes.get_mut(action.round).unwrap();

                if pre_votes.contains_key(&sender) {
                    return Err(Error::InvalidMessage(
                        "duplicated pre-process message from {:sender}".to_string(),
                    ));
                }

                pre_votes.insert(sender.clone(), action.clone());
            }
            Action::MainVote(action) => {}
        }
        Ok(())
    }

    fn check_message(&self, sender: &NodeId, msg: &Message) -> Result<()> {
        if msg.id != self.id {
            return Err(Error::InvalidMessage(
                "invalid ID. expected: {self.id}, got {msg.id}".to_string(),
            ));
        }

        match &msg.action {
            Action::PreVote(action) => {
                let sign_bytes = self.pre_vote_bytes_to_sign(&action.value)?;
                if !self
                    .pub_key_set
                    .public_key_share(sender)
                    .verify(&action.sig_share, &sign_bytes)
                {
                    return Err(Error::InvalidMessage(
                        "pre-vot has an invalid signature share".to_string(),
                    ));
                }

                if action.round == 1 {
                    // TODO:?
                    // Do we need to keep the justification and init-value as member of abba
                    // and here we compare both values?
                } else {
                }
            }
            Action::MainVote(action) => {}
        }

        Ok(())
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, msg: self::Message) -> Result<()> {
        let data = bincode::serialize(&msg)?;
        self.broadcaster.borrow_mut().broadcast(MODULE_NAME, data);
        self.receive_message(self.i, msg)?;
        Ok(())
    }

    // pre_vote_bytes_to_sign generates bytes for Pre-Vote signature share.
    // pre_vote_bytes_to_sign is same as serialized of $(ID, pre-vote, r, b)$ in spec.
    fn pre_vote_bytes_to_sign(&self, v: &PreVoteValue) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(
            self.id.clone(),
            "pre-vote",
            self.r,
            v.clone(),
        ))?)
    }

    // main_vote_bytes_to_sign generates bytes for Main-Vote signature share.
    // main_vote_bytes_to_sign is same as serialized of $(ID, main-vote, r, v)$ in spec.
    fn main_vote_bytes_to_sign(&self, v: &MainVoteValue) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(
            self.id.clone(),
            "main-vote",
            self.r,
            v.clone(),
        ))?)
    }

    // threshold is same as $t$ in spec
    fn threshold(&self) -> usize {
        self.pub_key_set.threshold()
    }

    fn get_pre_process_simple_majority_value(&self) -> bool {
        todo!();
        // let v = false;
        // for (_, msg) in self.pre_process_messages {

        // }
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
