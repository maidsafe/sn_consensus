pub(super) mod message;

mod error;
use blsttc::{PublicKeySet, PublicKeyShare, SecretKeyShare, Signature, SignatureShare};
use log::warn;

use self::error::{Error, Result};
use self::message::{
    Action, MainVoteAction, MainVoteValue, Message, PreVoteAction, PreVoteValue,
    PreVoteVoteJustification,
};
use super::hash::Hash32;
use super::NodeId;
use crate::mvba::abba::message::MainVoteJustification;
use crate::mvba::broadcaster::Broadcaster;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "abba";

/// The ABBA holds the information for Asynchronous Binary Byzantine Agreement protocol.
pub(crate) struct Abba {
    id: String, // this is same as $ID$ in spec
    i: NodeId,  // this is same as $i$ in spec
    r: usize,   // this is same as $r$ in spec
    subject: Hash32,
    pub_key_set: PublicKeySet,
    sec_key_share: SecretKeyShare,
    broadcaster: Rc<RefCell<Broadcaster>>,
    round_pre_votes: Vec<HashMap<NodeId, PreVoteAction>>,
    round_main_votes: Vec<HashMap<NodeId, MainVoteAction>>,
}

impl Abba {
    pub fn new(
        id: String,
        i: NodeId,
        subject: Hash32,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            id,
            i,
            r: 1,
            subject,
            pub_key_set,
            sec_key_share,
            broadcaster,
            round_pre_votes: Vec::new(),
            round_main_votes: Vec::new(),
        }
    }

    /// pre_vote starts the abba by broadcasting a pre-vote message.
    /// `value` is the initial value and should  set to One
    /// `proof` is the subject signature
    pub fn pre_vote(&mut self, value: PreVoteValue, proof: Signature) -> Result<()> {
        // Produce an S-signature share on the message: (ID, pre-vote, r, b).
        let sign_bytes = self.pre_vote_bytes_to_sign(&value)?;
        let sig_share = self.sec_key_share.sign(sign_bytes);
        let justification =
            PreVoteVoteJustification::RoundOneJustification(self.subject.clone(), proof);
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
            Action::MainVote(_) => {
                if self.r == 1 {
                    // For the first round
                } else {
                    // For round > 1

                    let main_votes = self
                        .round_main_votes
                        .get(self.r - 1)
                        .expect("main-votes for this round is not set");

                    if main_votes.len() == self.threshold() {
                        // How many votes are zero?
                        let zero_count = main_votes
                            .iter()
                            .filter(|(_, a)| a.value == MainVoteValue::Zero)
                            .count();

                        // How many votes are one?
                        let one_count = main_votes
                            .iter()
                            .filter(|(_, a)| a.value == MainVoteValue::One)
                            .count();

                        // How many votes are abstain?
                        let abstain_count = main_votes
                            .iter()
                            .filter(|(_, a)| a.value == MainVoteValue::Abstain)
                            .count();

                        let (value, justification) =
                            if zero_count == self.threshold() {
                                let sig =
                                    match &main_votes.iter().last().unwrap().1.justification {
                                        MainVoteJustification::NoAbstainJustification(sig) => sig,
                                        _ => return Err(Error::Generic(
                                            "protocol violated, invalid main-vote justification"
                                                .to_string(),
                                        )),
                                    };
                                (
                                    PreVoteValue::Zero,
                                    PreVoteVoteJustification::HardJustification(sig.clone()),
                                )
                            } else if one_count == self.threshold() {
                                let sig =
                                    match &main_votes.iter().last().unwrap().1.justification {
                                        MainVoteJustification::NoAbstainJustification(sig) => sig,
                                        _ => return Err(Error::Generic(
                                            "protocol violated, invalid main-vote justification"
                                                .to_string(),
                                        )),
                                    };
                                (
                                    PreVoteValue::One,
                                    PreVoteVoteJustification::HardJustification(sig.clone()),
                                )
                            } else if abstain_count == self.threshold() {
                                let sig =
                                    match &main_votes.iter().last().unwrap().1.justification {
                                        MainVoteJustification::NoAbstainJustification(sig) => sig,
                                        _ => return Err(Error::Generic(
                                            "protocol violated, invalid main-vote justification"
                                                .to_string(),
                                        )),
                                    };
                                (
                                    PreVoteValue::One,
                                    PreVoteVoteJustification::HardJustification(sig.clone()),
                                )
                            } else {
                                return Err(Error::Generic(
                                    "protocol violated, no pre-vote majority".to_string(),
                                ));
                            };

                        let majority_votes: HashMap<&usize, &MainVoteAction> =
                            if one_count > self.threshold() {
                                main_votes
                                    .iter()
                                    .filter(|(_, a)| a.value == MainVoteValue::One)
                                    .collect()
                            } else {
                                main_votes
                                    .iter()
                                    .filter(|(_, a)| a.value == MainVoteValue::Zero)
                                    .collect()
                            };

                        let sig_share: HashMap<&&NodeId, &SignatureShare> = majority_votes
                            .iter()
                            .map(|(n, a)| (n, &a.sig_share))
                            .collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        let pre_vote_value = PreVoteValue::One;
                        let sign_bytes = self.pre_vote_bytes_to_sign(&pre_vote_value)?;
                        let sig_share = self.sec_key_share.sign(sign_bytes);

                        let pre_vote_message = Message {
                            id: self.id.clone(),
                            action: Action::PreVote(PreVoteAction {
                                round: self.r,
                                value,
                                justification,
                                sig_share,
                            }),
                        };

                        self.broadcast(pre_vote_message)?;
                    }
                }
            }

            Action::PreVote(_) => {
                let pre_votes = self
                    .round_pre_votes
                    .get(self.r - 1)
                    .expect("messages for this round is not set");

                // Collect n − t valid and properly justified round-r pre-vote messages.
                if pre_votes.len() == self.threshold() {
                    // How many votes are zero?
                    let zero_count = pre_votes
                        .iter()
                        .filter(|(_, a)| a.value == PreVoteValue::Zero)
                        .count();

                    // How many votes are one?
                    let one_count = pre_votes
                        .iter()
                        .filter(|(_, a)| a.value == PreVoteValue::One)
                        .count();

                    let (value, justification) = if zero_count == self.threshold() {
                        // All votes are zero:
                        //   - value:  zero
                        //   - justification: combination of all pre-votes S-Signature shares
                        let sig_share: HashMap<&NodeId, &SignatureShare> =
                            pre_votes.iter().map(|(n, a)| (n, &a.sig_share)).collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        (
                            MainVoteValue::Zero,
                            MainVoteJustification::NoAbstainJustification(sig),
                        )
                    } else if one_count == self.threshold() {
                        // All votes are one:
                        //   - value:  one
                        //   - justification: combination of all pre-votes S-Signature shares
                        let sig_share: HashMap<&NodeId, &SignatureShare> =
                            pre_votes.iter().map(|(n, a)| (n, &a.sig_share)).collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        (
                            MainVoteValue::One,
                            MainVoteJustification::NoAbstainJustification(sig),
                        )
                    } else {
                        // there is a pre-vote for 0 and a pre-vote for 1 (conflicts):
                        //   - value:  abstain
                        //   - justification: two pre-votes S-Signature for zero and one

                        // TODO: unstable rust!
                        // let sig0 = pre_votes
                        //     .drain_filter(|_k, v| v.value == PreVoteValue::One)
                        //     .into_iter()
                        //     .last()
                        //     .unwrap()
                        //     .1
                        //     .justification;

                        // let sig1 = pre_votes
                        //     .drain_filter(|_k, v| v.value == PreVoteValue::Zero)
                        //     .into_iter()
                        //     .last()
                        //     .unwrap()
                        //     .1
                        //     .justification;

                        // (
                        //     MainVoteValue::Abstain,
                        //     MainVoteJustification::AbstainJustification(sig0, sig1),
                        // )

                        todo!()
                    };

                    let sign_bytes = self.main_vote_bytes_to_sign(&value)?;
                    let sig_share = self.sec_key_share.sign(sign_bytes);

                    let main_vote_message = Message {
                        id: self.id.clone(),
                        action: Action::MainVote(MainVoteAction {
                            round: self.r,
                            value,
                            sig_share,
                            justification: justification,
                        }),
                    };

                    self.broadcast(main_vote_message)?;

                    self.r += 1;
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
            Action::PreVote(action) => {
                // make sure we have the round messages
                while self.round_pre_votes.len() < action.round {
                    self.round_pre_votes.push(HashMap::new());
                }
                // TODO, @D_Rusu, please how to not unwrap here?
                let pre_votes = self.round_pre_votes.get_mut(action.round - 1).unwrap();

                if pre_votes.contains_key(&sender) {
                    return Err(Error::InvalidMessage(format!(
                        "duplicated pre-process message from {}",
                        sender
                    )));
                }

                pre_votes.insert(sender.clone(), action.clone());
            }
            Action::MainVote(action) => {}
        }
        Ok(())
    }

    fn check_message(&self, sender: &NodeId, msg: &Message) -> Result<()> {
        if msg.id != self.id {
            return Err(Error::InvalidMessage(format!(
                "invalid ID. expected: {}, got {}",
                self.id, msg.id
            )));
        }

        match &msg.action {
            Action::PreVote(action) => {
                let sign_bytes = self.pre_vote_bytes_to_sign(&action.value)?;
                if !self
                    .pub_key_set
                    .public_key_share(sender)
                    .verify(&action.sig_share, &sign_bytes)
                {
                    return Err(Error::InvalidMessage("invalid signature share".to_string()));
                }

                match &action.justification {
                    PreVoteVoteJustification::RoundOneJustification(subject, proof) => {
                        if action.round != 1 {
                            return Err(Error::InvalidMessage(format!(
                                "invalid round. expected 1, got {}",
                                action.round
                            )));
                        }

                        if subject != &self.subject {
                            return Err(Error::InvalidMessage(format!(
                                "invalid subject. expected {}, got {}",
                                self.subject, subject
                            )));
                        }

                        if !self
                            .pub_key_set
                            .public_key()
                            .verify(&proof, &subject.to_bytes())
                        {
                            return Err(Error::InvalidMessage("invalid proof".to_string()));
                        }

                        // A weaker validity:an honest party may only decide on a value
                        // for which it has the accompanying validating data.
                        if action.value != PreVoteValue::One {
                            return Err(Error::InvalidMessage("invalid value".to_string()));
                        }
                    }
                    _ => {
                        todo!()
                    }
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
        self.pub_key_set.threshold() + 1
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
