pub(super) mod message;

mod error;
use blsttc::{PublicKeySet, PublicKeyShare, SecretKeyShare};
use log::warn;

use self::error::{Error, Result};
use self::message::{Action, Message};
use super::NodeId;
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
    pre_process_messages: HashMap<NodeId, Message>,
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
            pre_process_messages: HashMap::new(),
        }
    }

    /// TODO: rename it to start or move it to new()???
    ///
    pub fn broadcast_pre_processing(&mut self) -> Result<()> {
        let sign_bytes = self.s0_bytes_to_sign(self.vi)?;
        // Generate an S0 -signature share on the message (ID, pre-process, Vi )
        let s0_sig_share = self.sec_key_share.sign(sign_bytes);
        let msg = Message {
            id: self.id.clone(),
            action: Action::PreProcess(self.vi, s0_sig_share),
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
            Action::PreProcess(v, s0_sig_share) => {
                // self.threshold() MUST be same as 2t + 1
                // Collect 2t + 1 proper pre-processing messages.
                if self.pre_process_messages.len() >= self.threshold() {
                    if self.r == 1 {
                        // If r = 1, let b be the simple majority of the received pre-processing votes.
                    }
                }
            }
        }

        Ok(())
    }

    pub fn is_decided(&self) -> bool {
        todo!()
    }

    fn add_message(&mut self, sender: &NodeId, msg: &Message) -> Result<()> {
        match &msg.action {
            Action::PreProcess(v, s0_sig_share) => {
                if self.pre_process_messages.contains_key(&sender) {
                    return Err(Error::InvalidMessage(
                        "duplicated pre-process message from {:sender}".to_string(),
                    ));
                }

                self.pre_process_messages.insert(sender.clone(), msg.clone());
            }
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
            Action::PreProcess(v, s0_sig_share) => {
                let sign_bytes = self.s0_bytes_to_sign(*v)?;
                if !self
                    .pub_key_set
                    .public_key_share(sender)
                    .verify(&s0_sig_share, &sign_bytes)
                {
                    return Err(Error::InvalidMessage(
                        "invalid s0-signature share".to_string(),
                    ));
                }
            }
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

    // s0_bytes_to_sign generates bytes for S0-signature share.
    // s0_bytes_to_sign is same as serialized of $(ID, pre-process, V_i)$ in spec.
    fn s0_bytes_to_sign(&self, v: bool) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(&self.id, "pre-process", v))?)
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
