pub(crate) mod error;
pub(crate) mod message;

use std::collections::hash_map::Entry::Vacant;
use std::collections::HashMap;

use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};

use self::error::{Error, Result};
use self::message::{Action, Message};
use super::hash::Hash32;
use super::tag::Tag;
use super::{bundle, MessageValidity, NodeId, Proposal};
use crate::mvba::broadcaster::Broadcaster;

// make_c_request_message creates the payload message to request a proposal
// from the the proposer
pub fn make_c_request_message(tag: Tag) -> bundle::Message {
    bundle::Message::Vcbc(Message {
        tag,
        action: Action::Request,
    })
}

// checks if the delivered proposal comes with a valid signature
pub fn verify_delivered_proposal(
    tag: &Tag,
    proposal: &Proposal,
    sig: &Signature,
    pks: &PublicKeySet,
) -> Result<bool> {
    let d = Hash32::calculate(proposal);
    let sign_bytes = c_ready_bytes_to_sign(tag, &d)?;
    Ok(pks.public_key().verify(sig, sign_bytes))
}

// c_ready_bytes_to_sign generates bytes that should be signed by each party
// as a witness of receiving the message.
// c_ready_bytes_to_sign is same as serialized of $(ID.j.s, c-ready, H(m))$ in spec
pub fn c_ready_bytes_to_sign(
    tag: &Tag,
    digest: &Hash32,
) -> std::result::Result<Vec<u8>, bincode::Error> {
    bincode::serialize(&(tag, "c-ready", digest))
}

// Protocol VCBC for verifiable and authenticated consistent broadcast.
pub(crate) struct Vcbc {
    tag: Tag, // Tag is a combination of Domain and proposer ID. It is unique in each VCBC instances.
    i: NodeId, // represents our unique identifier
    m_bar: Option<Proposal>, // represents the proposal data. If a proposal is not delivered yet, it is None.
    u_bar: Option<Signature>, // represents the signature of the delivered proposal. If the proposal is not delivered yet, it is None
    wd: HashMap<NodeId, SignatureShare>, // represents witness data. The witness data includes the signature shares of all the nodes that have participated in the protocol instance.
    rd: usize, // represents the number of signature shares received yet. Once this number reaches a threshold, the node can merge signatures.
    d: Option<Hash32>, // Memorizing the message digest
    pub_key_set: PublicKeySet,
    sec_key_share: SecretKeyShare,
    final_messages: HashMap<NodeId, Message>,
    message_validity: MessageValidity,
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
        tag: Tag,
        self_id: NodeId,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        message_validity: MessageValidity,
    ) -> Self {
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
        }
    }

    /// c_broadcast sends the messages `m` to all other parties.
    /// It also adds the message to message_log and process it.
    pub fn c_broadcast(&mut self, m: Proposal, broadcaster: &mut Broadcaster) -> Result<()> {
        debug_assert_eq!(self.i, self.tag.proposer);

        // Upon receiving message (ID.j.s, in, c-broadcast, m):
        // send (ID.j.s, c-send, m) to all parties
        let send_msg = Message {
            tag: self.tag.clone(),
            action: Action::Send(m),
        };
        self.broadcast(send_msg, broadcaster)
    }

    /// receive_message process the received message 'msg` from `initiator`
    pub fn receive_message(
        &mut self,
        initiator: NodeId,
        msg: Message,
        broadcaster: &mut Broadcaster,
    ) -> Result<()> {
        log::trace!(
            "party {} received {} message: {:?} from {}",
            self.i,
            msg.action_str(),
            msg,
            initiator
        );

        if msg.tag != self.tag {
            return Err(Error::InvalidMessage(format!(
                "invalid tag. expected {}, got {}",
                self.tag, msg.tag
            )));
        }

        match msg.action.clone() {
            Action::Send(m) => {
                // Upon receiving message (ID.j.s, c-send, m) from Pl:
                // if j = l and m̄ = ⊥ then
                if initiator == self.tag.proposer && self.m_bar.is_none() {
                    if !(self.message_validity)(initiator, &m) {
                        return Err(Error::InvalidMessage("invalid proposal".to_string()));
                    }
                    // m̄ ← m
                    self.m_bar = Some(m.clone());

                    let d = Hash32::calculate(&m);
                    self.d = Some(d);

                    // compute an S1-signature share ν on (ID.j.s, c-ready, H(m))
                    let sign_bytes = c_ready_bytes_to_sign(&self.tag, &d)?;
                    let s1 = self.sec_key_share.sign(sign_bytes);

                    let ready_msg = Message {
                        tag: self.tag.clone(),
                        action: Action::Ready(d, s1),
                    };

                    // send (ID.j.s, c-ready, H(m), ν) to Pj
                    self.send_to(ready_msg, self.tag.proposer, broadcaster)?;
                }
            }
            Action::Ready(msg_d, sig_share) => {
                let d = match self.d {
                    Some(d) => d,
                    None => return Err(Error::Generic("protocol violated. no digest".to_string())),
                };
                let sign_bytes = c_ready_bytes_to_sign(&self.tag, &d)?;

                if d != msg_d {
                    log::warn!("party {} received c-ready with unknown digest. expected {d:?}, got {msg_d:?}", self.i);
                    return Err(Error::Generic("Invalid digest".to_string()));
                }

                // Upon receiving message (ID.j.s, c-ready, d, νl) from Pl for the first time:
                if let Vacant(e) = self.wd.entry(initiator) {
                    let valid_sig = self
                        .pub_key_set
                        .public_key_share(initiator)
                        .verify(&sig_share, sign_bytes);

                    if !valid_sig {
                        log::warn!(
                            "party {} received c-ready with invalid signature share",
                            self.i
                        );
                    }

                    // if i = j and νl is a valid S1-signature share then
                    if self.i == msg.tag.proposer && valid_sig {
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
                            self.broadcast(final_msg, broadcaster)?;
                        }
                    }
                }
            }
            Action::Final(msg_d, sig) => {
                // Upon receiving message (ID.j.s, c-final, d, µ):
                let d = match self.d {
                    Some(d) => d,
                    None => {
                        log::warn!(
                            "party {} received c-final before receiving c-send, logging message",
                            self.i
                        );
                        try_insert(&mut self.final_messages, initiator, msg)?;
                        // requesting for the proposal
                        let request_msg = Message {
                            tag: self.tag.clone(),
                            action: Action::Request,
                        };
                        self.send_to(request_msg, initiator, broadcaster)?;

                        return Ok(());
                    }
                };

                let sign_bytes = c_ready_bytes_to_sign(&self.tag, &d)?;
                let valid_sig = self.pub_key_set.public_key().verify(&sig, sign_bytes);

                if !valid_sig {
                    log::warn!(
                        "party {} received c-ready with invalid signature share",
                        self.i
                    );
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
                        self.send_to(answer_msg, initiator, broadcaster)?;
                    }
                }
            }
            Action::Answer(m, u) => {
                // Upon receiving message (ID.j.s, c-answer, m, µ) from Pl :
                if self.u_bar.is_none() {
                    // if µ̄ = ⊥ and ...
                    let d = Hash32::calculate(&m);
                    let sign_bytes = c_ready_bytes_to_sign(&self.tag, &d)?;
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
            self.receive_message(initiator, final_msg, broadcaster)?;
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
    fn send_to(
        &mut self,
        msg: self::Message,
        to: NodeId,
        broadcaster: &mut Broadcaster,
    ) -> Result<()> {
        log::debug!("party {} sends {msg:?} to {}", self.i, to);

        if to == self.i {
            self.receive_message(self.i, msg, broadcaster)?;
        } else {
            broadcaster.send_to(Some(self.tag.proposer), bundle::Message::Vcbc(msg), to);
        }
        Ok(())
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, msg: self::Message, broadcaster: &mut Broadcaster) -> Result<()> {
        log::debug!("party {} broadcasts {msg:?}", self.i);

        broadcaster.broadcast(Some(self.i), bundle::Message::Vcbc(msg.clone()));
        self.receive_message(self.i, msg, broadcaster)?;
        Ok(())
    }

    // threshold is same as $t$ in spec
    fn threshold(&self) -> usize {
        self.pub_key_set.threshold() + 1
    }
}

#[cfg(test)]
#[path = "./test.rs"]
mod test;

#[cfg(test)]
#[path = "./proptest.rs"]
mod proptest;
