mod error;
pub(super) mod message;

use self::error::Result;
use self::message::{Message, Sig};
use super::hash::Hash32;
use super::NodeId;
use crate::mvba::broadcaster::Broadcaster;
use crate::mvba::vcbc::message::{MSG_ACTION_C_FINAL, MSG_ACTION_C_READY, MSG_ACTION_C_SEND};
use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use log::{debug, warn};
use std::cell::RefCell;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "vcbc";

// State transition
//
// +------------+       +------------+       +------------+       +------------+
// |    Send    | ----> |   Ready    | ----> |   Final    | ----> |  Delivered |
// +------------+       +------------+       +------------+       +------------+
//       \                    \                                         /
//        \--------------------\---------------------------------------/
//

#[derive(Debug)]
enum State {
    Send,
    Ready,
    Final,
    Delivered,
}

// Protocol VCBC for verifiable and authenticated consistent broadcast.
pub(crate) struct Vcbc {
    number: usize,                       // this is same as $n$ in spec
    threshold: usize,                    // this is same as $t$ in spec
    id: String,                          // this is same as $id$ in spec
    i: NodeId,                           // this is same as $i$ in spec
    j: NodeId,                           // this is same as $j$ in spec
    s: u32,                              // this is same as $s$ in spec
    m_bar: Option<Vec<u8>>,              // this is same as $\bar{m}$ in spec
    u_bar: Option<Signature>,            // this is same as $\bar{\mu}$ in spec
    wd: HashMap<NodeId, SignatureShare>, // this is same as $W_d$ in spec
    rd: usize,                           // this is same as $r_d$ in spec
    d: Option<Hash32>,                   // Memorizing the message digest
    pub_key_set: PublicKeySet,
    message_log: HashMap<String, Vec<(NodeId, Message)>>,
    broadcaster: Rc<RefCell<Broadcaster>>,
    sec_key_share: SecretKeyShare,

    state: State,
}

impl Vcbc {
    // TODO: how to fix clippy issue????
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        number: usize,
        threshold: usize,
        i: NodeId,
        id: String,
        j: NodeId,
        s: u32,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            number,
            threshold,
            id,
            i,
            j,
            s,
            m_bar: None,
            u_bar: None,
            wd: HashMap::new(),
            rd: 0,
            d: None,
            message_log: HashMap::new(),
            pub_key_set,
            sec_key_share,
            broadcaster,
            state: State::Send,
        }
    }

    // TODO: remove me
    #[allow(dead_code)]

    // c_broadcast sends the messages `msg` to all other parties.
    // It also adds the message to message_log and process it.
    pub fn c_broadcast(&mut self, msg: Vec<u8>) -> Result<()> {
        debug_assert_eq!(self.i, self.j);

        // Upon receiving message (ID.j.s, in, c-broadcast, m):
        // send (ID.j.s, c-send, m) to all parties
        let send_msg = Message {
            id: self.id.clone(),
            j: self.j,
            s: self.s,
            action: MSG_ACTION_C_SEND.to_string(),
            m: msg,
            sig: Sig::None,
        };
        self.broadcast(&send_msg)?;
        self.decide()
    }

    // log_message logs (adds) messages into the message_log
    pub fn log_message(&mut self, sender: NodeId, msg: Message) -> Result<()> {
        if msg.id != self.id || msg.j != self.j || msg.s != self.s {
            log::trace!("ignoring  message: {:?}. ", msg);
            return Ok(());
        }

        log::debug!("{:?} adding message: {:?}", self.state, msg);
        self.message_log
            .entry(msg.action.clone())
            .or_default()
            .push((sender, msg));

        Ok(())
    }

    pub fn is_delivered(&self) -> bool {
        self.u_bar.is_some()
    }

    // decides read messages from the message log and decides what to do based on
    // the current state of the system.
    pub fn decide(&mut self) -> Result<()> {
        // First we check if the message is c-delivered or not.
        self.check_is_delivered()?;

        match self.state {
            State::Send => {
                // Upon receiving message (ID.j.s, c-send, m) from Pl:
                match self.message_log.get(MSG_ACTION_C_SEND) {
                    Some(msgs) => {
                        // TODO: better way?
                        let msg_cloned = msgs.clone();
                        for (l, msg) in msg_cloned {
                            // if j = l and m̄ = ⊥ then
                            if l == self.j && self.m_bar.is_none() {
                                // m̄ ← m
                                self.m_bar = Some(msg.m);

                                // Memorizing the hash of message
                                self.d = Some(Hash32::calculate(self.m_bar.as_ref().unwrap()));

                                // compute an S1-signature share ν on (ID.j.s, c-ready, H(m))
                                let sign_bytes = self.sign_bytes();
                                let s1 = self.sec_key_share.sign(sign_bytes);
                                let ready_msg = Message {
                                    id: self.id.clone(),
                                    j: self.j,
                                    s: self.s,
                                    action: MSG_ACTION_C_READY.to_string(),
                                    m: self.d.as_ref().unwrap().to_bytes(),
                                    sig: Sig::SignatureShare(s1),
                                };

                                // send (ID.j.s, c-ready, H(m), ν) to Pj
                                self.send_to(&ready_msg, self.j)?;

                                self.state = State::Ready;
                                return self.decide();
                            }
                        }
                        Ok(())
                    }
                    None => Ok(()),
                }
            }
            State::Ready => {
                match self.message_log.get(MSG_ACTION_C_READY) {
                    Some(msgs) => {
                        // TODO: better way?
                        let msg_cloned = msgs.clone();
                        for (l, msg) in msg_cloned {
                            if !msg.m.eq(&self.d.as_ref().unwrap().as_fixed_bytes()) {
                                warn!(
                                    "c-ready has unknown digest. expected {:?}, got {:?}",
                                    self.d.as_ref().unwrap(),
                                    msg.m
                                );
                                continue;
                            }
                            let sign_bytes = self.sign_bytes();

                            // Upon receiving message (ID.j.s, c-ready, d, νl) from Pl for the first time:
                            if let Vacant(e) = self.wd.entry(l) {
                                if let Sig::SignatureShare(sig_share) = msg.sig {
                                    let valid_sig = self
                                        .pub_key_set
                                        .public_key_share(l)
                                        .verify(&sig_share, sign_bytes);

                                    if !valid_sig {
                                        warn!("c-ready has has invalid signature share");
                                    }

                                    // if i = j and νl is a valid S1-signature share then
                                    if self.i == msg.j && valid_sig {
                                        // Wd ← Wd ∪ {νl}
                                        e.insert(sig_share);

                                        //  rd ← rd + 1
                                        self.rd += 1;

                                        // if rd = n+t+1/2 then
                                        if self.rd == (self.number + self.threshold + 1) / 2 {
                                            // combine the shares in Wd to an S1 -threshold signature µ
                                            let sig = self
                                                .pub_key_set
                                                .combine_signatures(self.wd.iter())?;

                                            let final_msg = Message {
                                                id: self.id.clone(),
                                                j: self.j,
                                                s: self.s,
                                                action: MSG_ACTION_C_FINAL.to_string(),
                                                m: self.d.as_ref().unwrap().to_bytes(),
                                                sig: Sig::Signature(sig),
                                            };

                                            // send (ID.j.s, c-final, d, µ) to all parties
                                            self.broadcast(&final_msg)?;

                                            self.state = State::Final;
                                            return self.decide();
                                        }
                                    }
                                }
                            }
                        }
                        Ok(())
                    }
                    None => Ok(()),
                }
            }
            State::Final => {
                // Nothing to do here.
                // We call check_is_delivered function at the bebging of this function
                Ok(())
            }
            State::Delivered => {
                // Nothing to do here.
                // Message is delivered
                Ok(())
            }
        }
    }

    // ---- Private methods ---

    fn sign_bytes(&mut self) -> Vec<u8> {
        let msg = Message {
            id: self.id.clone(),
            j: self.j,
            s: self.s,
            action: MSG_ACTION_C_READY.to_string(),
            m: self.d.as_ref().unwrap().to_bytes(),
            sig: Sig::None,
        };
        bincode::serialize(&msg).unwrap()
    }

    fn check_is_delivered(&mut self) -> Result<()> {
        // It's delivered, just return here
        if self.is_delivered() {
            return Ok(());
        }

        match self.message_log.get(MSG_ACTION_C_FINAL) {
            Some(msgs) => {
                // TODO: better way?
                let msg_cloned = msgs.clone();
                for (_l, msg) in msg_cloned {
                    if self.d.is_some() {
                        if let Sig::Signature(sig) = &msg.sig {
                            let sign_bytes = self.sign_bytes();
                            let valid_sig = self.pub_key_set.public_key().verify(sig, sign_bytes);

                            if valid_sig {
                                debug!("a valid c-final message received: {:?}", msg.clone());
                                self.u_bar = Some(sig.clone());
                                self.state = State::Delivered;

                                return Ok(());
                            }
                        }
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    // send_to sends the message `msg` to the corresponding peer `to`.
    // If the `to` is us, it adds the  message to our messages log.
    fn send_to(&mut self, msg: &self::Message, to: NodeId) -> Result<()> {
        let data = bincode::serialize(msg).unwrap();
        if to == self.i {
            self.log_message(self.i, msg.clone())
        } else {
            self.broadcaster.borrow_mut().send_to(MODULE_NAME, data, to);
            Ok(())
        }
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, msg: &self::Message) -> Result<()> {
        let data = bincode::serialize(msg)?;
        self.broadcaster.borrow_mut().broadcast(MODULE_NAME, data);
        self.log_message(self.i, msg.clone())
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
