pub(super) mod context;
pub(super) mod message;
pub(super) mod state;

mod error;

use self::error::Result;
use self::message::{Message, Sig, MSG_ACTION_C_BROADCAST, MSG_ACTION_C_FINAL};
use super::hash::Hash32;
use super::NodeId;
use crate::mvba::broadcaster::Broadcaster;
use crate::mvba::hash::hash;
use crate::mvba::vcbc::message::{MSG_ACTION_C_READY, MSG_ACTION_C_SEND};
use blsttc::{PublicKeySet, SecretKeyShare, SignatureShare};
use log::warn;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "vcbc";

#[derive(Debug)]
enum State {
    Broadcast,
    Send,
    Ready,
    Final,
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
    u_bar: Option<Vec<u8>>,              // this is same as $\bar{\mu}$ in spec
    wd: HashMap<NodeId, SignatureShare>, // this is same as $W_d$ in spec
    rd: usize,                           // this is same as $r_d$ in spec
    d: Option<Hash32>,                   // Memorizing the message digest
    pub_key_set: PublicKeySet,
    message_log: HashMap<String, Vec<(NodeId, Message)>>,
    broadcaster: Rc<RefCell<Broadcaster>>,
    sec_key_share: SecretKeyShare,
    delivered: bool,

    state: State,
}

impl Vcbc {
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
            delivered: false,
            state: State::Broadcast,
        }
    }

    // sending c-broadcast messages
    pub fn c_broadcast(&mut self, m: Vec<u8>) -> Result<()> {
        debug_assert_eq!(self.i, self.j);

        let msg = Message {
            id: self.id.clone(),
            j: self.i,
            s: self.s,
            action: MSG_ACTION_C_BROADCAST.to_string(),
            m,
            sig: Sig::None,
        };
        self.broadcast(&msg);
        self.process_message(self.i, msg)
    }

    pub fn process_message(&mut self, sender: NodeId, msg: Message) -> Result<()> {
        log::debug!("{:?} adding message: {:?}", self.state, msg);

        self.log_message(sender, msg)?;
        self.decide()
    }

    pub fn is_delivered(&self) -> bool {
        self.delivered
    }

    // ---- Private methods ---

    fn decide(&mut self) -> Result<()> {
        match self.state {
            State::Broadcast => {
                // Upon receiving message (ID.j.s, in, c-broadcast, m):
                match self.message_log.get(MSG_ACTION_C_BROADCAST) {
                    Some(msgs) => {
                        let broadcast_msg = &msgs[0].1;
                        let send_msg = Message {
                            id: self.id.clone(),
                            j: self.j,
                            s: self.s,
                            action: MSG_ACTION_C_SEND.to_string(),
                            m: broadcast_msg.m.clone(),
                            sig: Sig::None,
                        };

                        // send (ID.j.s, c-send, m) to all parties
                        self.broadcast(&send_msg);

                        self.state = State::Send;
                        self.decide()
                    }
                    None => Ok(()),
                }
            }
            State::Send => {
                // Upon receiving message (ID.j.s, c-send, m) from Pl:
                match self.message_log.get(MSG_ACTION_C_SEND) {
                    Some(msgs) => {
                        // TODO: better way?
                        let msg_cloned = msgs.clone();
                        for (l, msg) in msg_cloned {
                            // if j = l and m̄ = ⊥ then
                            if l == self.j && self.m_bar == None {
                                // m̄ ← m
                                self.m_bar = Some(msg.m.clone());

                                // compute an S1-signature share ν on (ID.j.s, c-ready, H(m))
                                let d = hash(&msg.m);
                                let mut ready_msg = Message {
                                    id: self.id.clone(),
                                    j: self.j,
                                    s: self.s,
                                    action: MSG_ACTION_C_READY.to_string(),
                                    m: d.0.to_vec(),
                                    sig: Sig::None,
                                };
                                let sig_bytes = bincode::serialize(&msg)?;
                                let s1 = self.sec_key_share.sign(sig_bytes);
                                ready_msg.sig = Sig::SignatureShare(s1);

                                // send (ID.j.s, c-ready, H(m), ν) to Pj
                                self.send_to(&ready_msg, self.j);

                                self.d = Some(d);
                                self.state = State::Send;
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
                            if !msg.m.eq(&self.d.as_ref().unwrap().0) {
                                warn!(
                                    "c-ready has unknown digest. expected {:?}, got {:?}",
                                    self.d.as_ref().unwrap(),
                                    msg.m
                                );
                                continue;
                            }
                            // Upon receiving message (ID.j.s, c-ready, d, νl) from Pl for the first time:
                            if !self.wd.contains_key(&l) {
                                match msg.sig {
                                    Sig::SignatureShare(sig_share) => {
                                        let valid_sig = self
                                            .pub_key_set
                                            .public_key_share(l)
                                            .verify(&sig_share, self.d.as_ref().unwrap().0);

                                        if !valid_sig {
                                            warn!("c-ready has has invalid signature share");
                                        }

                                        // if i = j and νl is a valid S1-signature share then
                                        if self.i == msg.j && valid_sig {
                                            // Wd ← Wd ∪ {νl}
                                            self.wd.insert(l, sig_share);

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
                                                    m: self.d.as_ref().unwrap().0.to_vec(),
                                                    sig: Sig::Signature(sig),
                                                };

                                                // send (ID.j.s, c-final, d, µ) to all parties
                                                self.broadcast(&final_msg);

                                                self.state = State::Final;
                                                return self.decide();
                                            }
                                        }
                                    }
                                    _ => {
                                        warn!("c-ready message without signature share: {:?}", msg);
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
                todo!()
            }
        }
    }

    fn send_to(&self, msg: &self::Message, to: NodeId) {
        let data = bincode::serialize(msg).unwrap();
        self.broadcaster.borrow_mut().send_to(MODULE_NAME, data, to);
    }

    fn broadcast(&self, msg: &self::Message) {
        let data = bincode::serialize(msg).unwrap();
        self.broadcaster.borrow_mut().broadcast(MODULE_NAME, data);
    }

    fn log_message(&mut self, sender: NodeId, msg: Message) -> Result<()> {
        if msg.id != self.id || msg.j != self.j || msg.s != self.s {
            log::trace!("ignoring  message: {:?}. ", msg);
            return Ok(());
        }

        self.message_log
            .entry(msg.action.clone())
            .or_insert(Vec::new())
            .push((sender, msg));

        Ok(())
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
