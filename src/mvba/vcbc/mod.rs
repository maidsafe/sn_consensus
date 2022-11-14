mod error;
pub(super) mod message;

use self::error::{Error, Result};
use self::message::{Action, Message, Tag};
use super::hash::Hash32;
use super::NodeId;
use crate::mvba::broadcaster::Broadcaster;
use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use log::warn;
use std::cell::RefCell;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "vcbc";

// Protocol VCBC for verifiable and authenticated consistent broadcast.
pub(crate) struct Vcbc {
    tag: Tag,                            // this is same as $Tag$ in spec
    i: NodeId,                           // this is same as $i$ in spec
    m_bar: Option<Vec<u8>>,              // this is same as $\bar{m}$ in spec
    u_bar: Option<Signature>,            // this is same as $\bar{\mu}$ in spec
    wd: HashMap<NodeId, SignatureShare>, // this is same as $W_d$ in spec
    rd: usize,                           // this is same as $r_d$ in spec
    d: Option<Hash32>,                   // Memorizing the message digest
    pub_key_set: PublicKeySet,
    final_messages: HashMap<NodeId, Message>,
    broadcaster: Rc<RefCell<Broadcaster>>,
    sec_key_share: SecretKeyShare,
}

/// Tries to insert a key-value pair into the map.
///
/// If the map already had this key present, nothing is updated, and
/// `DuplicatedMessage` error is returned.
/// TODO: replace it with unstable try_insert function
fn try_insert(map: &mut HashMap<NodeId, Message>, k: NodeId, v: Message) -> Result<()> {
    if let std::collections::hash_map::Entry::Vacant(e) = map.entry(k) {
        e.insert(v);
        Ok(())
    } else {
        Err(Error::DuplicatedMessage(k, v.action_str().to_string()))
    }
}

impl Vcbc {
    pub fn new(
        i: NodeId,
        tag: Tag,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        debug_assert_eq!(i, broadcaster.borrow().self_id());

        Self {
            i,
            tag,
            m_bar: None,
            u_bar: None,
            wd: HashMap::new(),
            rd: 0,
            d: None,
            final_messages: HashMap::new(),
            pub_key_set,
            sec_key_share,
            broadcaster,
        }
    }

    // TODO: remove me
    #[allow(dead_code)]

    // c_broadcast sends the messages `m` to all other parties.
    // It also adds the message to message_log and process it.
    pub fn c_broadcast(&mut self, m: Vec<u8>) -> Result<()> {
        debug_assert_eq!(self.i, self.tag.j);

        // Upon receiving message (ID.j.s, in, c-broadcast, m):
        // send (ID.j.s, c-send, m) to all parties
        let send_msg = Message {
            tag: self.tag.clone(),
            action: Action::Send(m),
        };
        self.broadcast(&send_msg)
    }

    // log_message logs (adds) messages into the message_log
    pub fn receive_message(&mut self, sender: NodeId, msg: Message) -> Result<()> {
        if msg.tag != self.tag {
            log::trace!("invalid tag, ignoring message.: {:?}. ", msg);
            return Ok(());
        }

        log::debug!("received {} message: {:?}", msg.action_str(), msg);
        match msg.action.clone() {
            Action::Send(m) => {
                // Upon receiving message (ID.j.s, c-send, m) from Pl:
                // if j = l and m̄ = ⊥ then
                if sender == self.tag.j && self.m_bar.is_none() {
                    // m̄ ← m
                    self.m_bar = Some(m.clone());

                    let d = Hash32::calculate(&m);
                    self.d = Some(d.clone());

                    // compute an S1-signature share ν on (ID.j.s, c-ready, H(m))
                    let sign_bytes = self.c_ready_bytes_to_sign(&d)?;
                    let s1 = self.sec_key_share.sign(sign_bytes);

                    let ready_msg = Message {
                        tag: self.tag.clone(),
                        action: Action::Ready(d, s1),
                    };

                    // send (ID.j.s, c-ready, H(m), ν) to Pj
                    self.send_to(&ready_msg, self.tag.j)?;
                }
            }
            Action::Ready(msg_d, sig_share) => {
                let d = match &self.d {
                    Some(d) => d,
                    None => return Err(Error::Generic("protocol violated. no digest".to_string())),
                };
                let sign_bytes = self.c_ready_bytes_to_sign(d)?;

                if d != &msg_d {
                    warn!(
                        "c-ready has unknown digest. expected {:?}, got {:?}",
                        d, msg_d
                    );
                    return Err(Error::Generic("Invalid digest".to_string()));
                }

                // Upon receiving message (ID.j.s, c-ready, d, νl) from Pl for the first time:
                if let Vacant(e) = self.wd.entry(sender) {
                    let valid_sig = self
                        .pub_key_set
                        .public_key_share(sender)
                        .verify(&sig_share, &sign_bytes);

                    if !valid_sig {
                        warn!("c-ready has has invalid signature share");
                    }

                    // if i = j and νl is a valid S1-signature share then
                    if self.i == msg.tag.j && valid_sig {
                        // Wd ← Wd ∪ {νl}
                        e.insert(sig_share);

                        //  rd ← rd + 1
                        self.rd += 1;

                        // self.threshold() MUST be same as n+t+1/2
                        // spec: if rd = n+t+1/2 then
                        if self.rd > self.threshold() {
                            // combine the shares in Wd to an S1 -threshold signature µ
                            let sig = self.pub_key_set.combine_signatures(self.wd.iter())?;

                            let final_msg = Message {
                                tag: self.tag.clone(),
                                action: Action::Final(d.clone(), sig),
                            };

                            // send (ID.j.s, c-final, d, µ) to all parties
                            self.broadcast(&final_msg)?;
                        }
                    }
                }
            }
            Action::Final(msg_d, sig) => {
                // Upon receiving message (ID.j.s, c-final, d, µ):
                let d = match &self.d {
                    Some(d) => d,
                    None => {
                        warn!("received c-final before receiving s-send, logging message");
                        try_insert(&mut self.final_messages, sender, msg)?;
                        return Ok(());
                    }
                };

                let sign_bytes = self.c_ready_bytes_to_sign(d)?;
                let valid_sig = self.pub_key_set.public_key().verify(&sig, sign_bytes);

                if !valid_sig {
                    warn!("c-ready has has invalid signature share");
                }

                // if H(m̄) = d and µ̄ = ⊥ and µ is a valid S1 -signature then
                if d == &msg_d && self.u_bar.is_none() && valid_sig {
                    // µ̄ ← µ
                    self.u_bar = Some(sig);
                }
            }
        }

        for (sender, final_msg) in std::mem::take(&mut self.final_messages) {
            self.receive_message(sender, final_msg)?;
        }

        Ok(())
    }

    pub fn is_delivered(&self) -> bool {
        self.u_bar.is_some()
    }

    #[allow(dead_code)]
    pub fn read_delivered(&self) -> Option<(Vec<u8>, Signature)> {
        if let (Some(m), Some(u)) = (&self.m_bar, &self.u_bar) {
            Some((m.clone(), u.clone()))
        } else {
            None
        }
    }

    // bytes_to_sign generates bytes that should be signed by each party.
    // bytes_to_sign is same as serialized of (ID.j.s, c-ready, H(m)) in spec.
    fn c_ready_bytes_to_sign(&self, digest: &Hash32) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(&self.tag, "c-ready", digest))?)
    }

    // send_to sends the message `msg` to the corresponding peer `to`.
    // If the `to` is us, it adds the  message to our messages log.
    fn send_to(&mut self, msg: &self::Message, to: NodeId) -> Result<()> {
        let data = bincode::serialize(msg).unwrap();
        if to == self.i {
            self.receive_message(self.i, msg.clone())?;
        } else {
            self.broadcaster.borrow_mut().send_to(MODULE_NAME, data, to);
        }
        Ok(())
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, msg: &self::Message) -> Result<()> {
        let data = bincode::serialize(msg)?;
        self.broadcaster.borrow_mut().broadcast(MODULE_NAME, data);
        self.receive_message(self.i, msg.clone())?;
        Ok(())
    }

    // threshold is same as $t$ in spec
    fn threshold(&self) -> usize {
        self.pub_key_set.threshold()
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
