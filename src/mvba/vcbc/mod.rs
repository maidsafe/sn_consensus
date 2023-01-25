pub(crate) mod error;
pub mod message;

use std::cell::RefCell;
use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;
use std::rc::Rc;

use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};

use self::error::{Error, Result};
use self::message::{Action, Message, Tag};
use super::hash::Hash32;
use super::{MessageValidity, NodeId, Proposal};
use crate::mvba::broadcaster::Broadcaster;

pub(crate) const MODULE_NAME: &str = "vcbc";

// make_c_request_message creates the payload message to request a proposal
// from the the proposer
pub fn make_c_request_message(
    id: &str,
    proposer: NodeId,
) -> std::result::Result<Vec<u8>, bincode::Error> {
    let msg = Message {
        tag: Tag {
            id: id.to_string(),
            j: proposer,
            s: 0,
        },
        action: Action::Request,
    };
    bincode::serialize(&msg)
}

// c_ready_bytes_to_sign generates bytes that should be signed by each party
// as a wittiness of receiving the message.
// c_ready_bytes_to_sign is same as serialized of $(ID.j.s, c-ready, H(m))$ in spec
pub fn c_ready_bytes_to_sign(
    id: &str,
    proposer: &NodeId,
    digest: &Hash32,
) -> std::result::Result<Vec<u8>, bincode::Error> {
    bincode::serialize(&(id, proposer, 0, "c-ready", digest))
}

// Protocol VCBC for verifiable and authenticated consistent broadcast.
pub(crate) struct Vcbc {
    tag: Tag,                            // this is same as $Tag$ in spec
    i: NodeId,                           // this is same as $i$ in spec
    m_bar: Option<Proposal>,             // this is same as $\bar{m}$ in spec
    u_bar: Option<Signature>,            // this is same as $\bar{\mu}$ in spec
    wd: HashMap<NodeId, SignatureShare>, // this is same as $W_d$ in spec
    rd: usize,                           // this is same as $r_d$ in spec
    d: Option<Hash32>,                   // Memorizing the message digest
    pub_key_set: PublicKeySet,
    sec_key_share: SecretKeyShare,
    final_messages: HashMap<NodeId, Message>,
    message_validity: MessageValidity,
    broadcaster: Rc<RefCell<Broadcaster>>,
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
        id: String,
        self_id: NodeId,
        proposer: NodeId,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        message_validity: MessageValidity,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        debug_assert_eq!(self_id, broadcaster.borrow().self_id());

        let tag = Tag::new(&id, proposer, 0);

        Self {
            tag,
            i: self_id,
            m_bar: None,
            u_bar: None,
            wd: HashMap::new(),
            rd: 0,
            d: None,
            final_messages: HashMap::new(),
            pub_key_set,
            sec_key_share,
            message_validity,
            broadcaster,
        }
    }

    /// c_broadcast sends the messages `m` to all other parties.
    /// It also adds the message to message_log and process it.
    pub fn c_broadcast(&mut self, m: Proposal) -> Result<()> {
        debug_assert_eq!(self.i, self.tag.j);

        // Upon receiving message (ID.j.s, in, c-broadcast, m):
        // send (ID.j.s, c-send, m) to all parties
        let send_msg = Message {
            tag: self.tag.clone(),
            action: Action::Send(m),
        };
        self.broadcast(send_msg)
    }

    /// receive_message process the received message 'msg` from `initiator`
    pub fn receive_message(&mut self, initiator: NodeId, msg: Message) -> Result<()> {
        log::debug!(
            "received {} message: {:?} from {}",
            msg.action_str(),
            msg,
            initiator
        );

        if msg.tag != self.tag {
            return Err(Error::InvalidMessage(format!(
                "invalid tag. expected {:?}, got {:?}",
                self.tag, msg.tag
            )));
        }

        match msg.action.clone() {
            Action::Send(m) => {
                // Upon receiving message (ID.j.s, c-send, m) from Pl:
                // if j = l and m̄ = ⊥ then
                if initiator == self.tag.j && self.m_bar.is_none() {
                    if !(self.message_validity)(initiator, &m) {
                        return Err(Error::InvalidMessage("invalid proposal".to_string()));
                    }
                    // m̄ ← m
                    self.m_bar = Some(m.clone());

                    let d = Hash32::calculate(&m);
                    self.d = Some(d);

                    // compute an S1-signature share ν on (ID.j.s, c-ready, H(m))
                    let sign_bytes = c_ready_bytes_to_sign(&self.tag.id, &self.tag.j, &d)?;
                    let s1 = self.sec_key_share.sign(sign_bytes);

                    let ready_msg = Message {
                        tag: self.tag.clone(),
                        action: Action::Ready(d, s1),
                    };

                    // send (ID.j.s, c-ready, H(m), ν) to Pj
                    self.send_to(ready_msg, self.tag.j)?;
                }
            }
            Action::Ready(msg_d, sig_share) => {
                let d = match self.d {
                    Some(d) => d,
                    None => return Err(Error::Generic("protocol violated. no digest".to_string())),
                };
                let sign_bytes = c_ready_bytes_to_sign(&self.tag.id, &self.tag.j, &d)?;

                if d != msg_d {
                    log::warn!("c-ready has unknown digest. expected {d:?}, got {msg_d:?}");
                    return Err(Error::Generic("Invalid digest".to_string()));
                }

                // Upon receiving message (ID.j.s, c-ready, d, νl) from Pl for the first time:
                if let Vacant(e) = self.wd.entry(initiator) {
                    let valid_sig = self
                        .pub_key_set
                        .public_key_share(initiator)
                        .verify(&sig_share, sign_bytes);

                    if !valid_sig {
                        log::warn!("c-ready has has invalid signature share");
                    }

                    // if i = j and νl is a valid S1-signature share then
                    if self.i == msg.tag.j && valid_sig {
                        // Wd ← Wd ∪ {νl}
                        e.insert(sig_share);

                        //  rd ← rd + 1
                        self.rd += 1;

                        // self.threshold() MUST be same as n+t+1/2
                        // spec: if rd = n+t+1/2 then
                        if self.rd >= self.threshold() {
                            // combine the shares in Wd to an S1 -threshold signature µ
                            let sig = self.pub_key_set.combine_signatures(self.wd.iter())?;

                            let final_msg = Message {
                                tag: self.tag.clone(),
                                action: Action::Final(d, sig),
                            };

                            // send (ID.j.s, c-final, d, µ) to all parties
                            self.broadcast(final_msg)?;
                        }
                    }
                }
            }
            Action::Final(msg_d, sig) => {
                // Upon receiving message (ID.j.s, c-final, d, µ):
                let d = match self.d {
                    Some(d) => d,
                    None => {
                        log::warn!("received c-final before receiving c-send, logging message");
                        try_insert(&mut self.final_messages, initiator, msg)?;
                        // requesting for the proposal
                        let request_msg = Message {
                            tag: self.tag.clone(),
                            action: Action::Request,
                        };
                        self.send_to(request_msg, initiator)?;

                        return Ok(());
                    }
                };

                let sign_bytes = c_ready_bytes_to_sign(&self.tag.id, &self.tag.j, &d)?;
                let valid_sig = self.pub_key_set.public_key().verify(&sig, sign_bytes);
                if !valid_sig {
                    log::warn!("c-ready has has invalid signature share");
                }

                // if H(m̄) = d and µ̄ = ⊥ and µ is a valid S1-signature then
                if d == msg_d && self.u_bar.is_none() && valid_sig {
                    // µ̄ ← µ
                    self.u_bar = Some(sig);
                }
            }
            Action::Request => {
                // Upon receiving message (ID.j.s, c-request) from Pl :
                if let Some(u) = &self.u_bar {
                    // if µ̄  != ⊥ then

                    // proposal is known because we have the valid signature
                    debug_assert!(self.m_bar.is_some());
                    if let Some(m) = &self.m_bar {
                        let answer_msg = Message {
                            tag: self.tag.clone(),
                            action: Action::Answer(m.clone(), u.clone()),
                        };

                        // send (ID.j.s, c-answer, m̄, µ̄) to Pl
                        self.send_to(answer_msg, initiator)?;
                    }
                }
            }
            Action::Answer(m, u) => {
                // Upon receiving message (ID.j.s, c-answer, m, µ) from Pl :
                if self.u_bar.is_none() {
                    // if µ̄ = ⊥ and ...
                    let d = Hash32::calculate(&m);
                    let sign_bytes = c_ready_bytes_to_sign(&self.tag.id, &self.tag.j, &d)?;
                    if self.pub_key_set.public_key().verify(&u, sign_bytes) {
                        // ... µ is a valid S1 -signature on (ID.j.s, c-ready, H(m)) then
                        // µ̄ ← µ
                        // m̄ ← m
                        self.u_bar = Some(u);
                        self.m_bar = Some(m);
                    }
                }
            }
        }

        for (initiator, final_msg) in std::mem::take(&mut self.final_messages) {
            self.receive_message(initiator, final_msg)?;
        }

        Ok(())
    }

    pub fn read_delivered(&self) -> Option<(Proposal, Signature)> {
        if let (Some(proposal), Some(sig)) = (self.m_bar.clone(), self.u_bar.clone()) {
            Some((proposal, sig))
        } else {
            None
        }
    }

    // send_to sends the message `msg` to the corresponding peer `to`.
    // If the `to` is us, it adds the  message to our messages log.
    fn send_to(&mut self, msg: self::Message, to: NodeId) -> Result<()> {
        let data = bincode::serialize(&msg)?;
        if to == self.i {
            self.receive_message(self.i, msg)?;
        } else {
            self.broadcaster
                .borrow_mut()
                .send_to(MODULE_NAME, Some(self.tag.j), data, to);
        }
        Ok(())
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, msg: self::Message) -> Result<()> {
        let data = bincode::serialize(&msg)?;
        self.broadcaster
            .borrow_mut()
            .broadcast(MODULE_NAME, Some(self.i), data);
        self.receive_message(self.i, msg)?;
        Ok(())
    }

    // threshold is same as $t$ in spec
    fn threshold(&self) -> usize {
        self.pub_key_set.threshold() + 1
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
