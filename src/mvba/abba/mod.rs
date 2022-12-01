// TODO: apply section 5.3.3. Further Optimizations

pub(super) mod message;

mod error;
use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use log::{debug};

use self::error::{Error, Result};
use self::message::{
    Action, MainVoteAction, MainVoteValue, Message, PreVoteAction, PreVoteJustification,
    PreVoteValue,
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
    id: String,                  // this is same as $ID$ in spec
    i: NodeId,                   // this is same as $i$ in spec
    r: usize,                    // this is same as $r$ in spec
    decided_value: Option<bool>, // TODO: should be boolean?
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
            decided_value: None,
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
        let sign_bytes = self.pre_vote_bytes_to_sign(self.r, &value)?;
        let sig_share = self.sec_key_share.sign(sign_bytes);
        let justification =
            PreVoteJustification::RoundOneJustification(self.subject.clone(), proof);
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
        if !self.add_message(&sender, &msg)? {
            return Ok(());
        }

        match &msg.action {
            Action::MainVote(action) => {
                if action.round + 1 != self.r {
                    return Ok(());
                }
                // 1. PRE-VOTE step.
                // Note: In weaker validity mode, round 1 comes with the external justification.

                // if r > 1, ...
                if self.r > 1 {
                    // select n − t properly justified main-votes from round r − 1
                    let main_votes = match self.get_main_votes_by_round(self.r - 1) {
                        Some(v) => v,
                        None => {
                            debug!("no main-votes for this round: {}", self.r);
                            return Ok(());
                        }
                    };

                    if main_votes.len() == self.threshold() {
                        // How many votes are 0?
                        let zero_count = main_votes
                            .iter()
                            .filter(|(_, a)| a.value == MainVoteValue::Zero)
                            .count();

                        // How many votes are 1?
                        let one_count = main_votes
                            .iter()
                            .filter(|(_, a)| a.value == MainVoteValue::One)
                            .count();

                        // How many votes are abstain?
                        let abstain_count = main_votes
                            .iter()
                            .filter(|(_, a)| a.value == MainVoteValue::Abstain)
                            .count();

                        let (value, justification) = if zero_count > 0 {
                            // if there is a main-vote for 0,
                            let sig = match &main_votes.iter().last().unwrap().1.justification {
                                MainVoteJustification::NoAbstainJustification(sig) => sig,
                                _ => {
                                    return Err(Error::Generic(
                                        "protocol violated, invalid main-vote justification"
                                            .to_string(),
                                    ))
                                }
                            };
                            // hard pre-vote for 0
                            (
                                PreVoteValue::Zero,
                                PreVoteJustification::HardJustification(sig.clone()),
                            )
                        } else if one_count > 1 {
                            // if there is a main-vote for 1,
                            let sig = match &main_votes.iter().last().unwrap().1.justification {
                                MainVoteJustification::NoAbstainJustification(sig) => sig,
                                _ => {
                                    return Err(Error::Generic(
                                        "protocol violated, invalid main-vote justification"
                                            .to_string(),
                                    ))
                                }
                            };
                            // hard pre-vote for 1
                            (
                                PreVoteValue::One,
                                PreVoteJustification::HardJustification(sig.clone()),
                            )
                        } else if abstain_count == self.threshold() {
                            // if all main-votes are abstain,
                            let sig = match &main_votes.iter().last().unwrap().1.justification {
                                MainVoteJustification::AbstainJustification(_, _) => {
                                    let sig_share: HashMap<&NodeId, &SignatureShare> =
                                        main_votes.iter().map(|(n, a)| (n, &a.sig_share)).collect();
                                    self.pub_key_set.combine_signatures(sig_share)?
                                }
                                _ => {
                                    return Err(Error::Generic(
                                        "protocol violated, invalid main-vote justification"
                                            .to_string(),
                                    ))
                                }
                            };
                            // soft pre-vote for 1
                            // Coin value bias to 1 in weaker validity mode.
                            (
                                PreVoteValue::One,
                                PreVoteJustification::SoftJustification(sig),
                            )
                        } else {
                            return Err(Error::Generic(
                                "protocol violated, no pre-vote majority".to_string(),
                            ));
                        };

                        // Produce an S-signature share on the message `(ID, pre-vote, r, b)`
                        let sign_bytes = self.pre_vote_bytes_to_sign(self.r, &value)?;
                        let sig_share = self.sec_key_share.sign(sign_bytes);

                        // Send to all parties the message `(ID, pre-vote, r, b, justification, signature share)`
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

            Action::PreVote(action) => {
                if action.round != self.r {
                    return Ok(());
                }
                // Let's check pre-votes:

                // HECK FOR DECISION. Collect n −t valid and properly justified main-votes of round r .
                // If these are all main-votes for b ∈ {0, 1}, then decide the value b for ID
                let mut decided_value = None;
                let pre_votes = match self.get_pre_votes_by_round(self.r) {
                    Some(v) => v,
                    None => {
                        debug!("no pre-votes for this round: {}", self.r);
                        return Ok(());
                    }
                };
                // Collect n − t valid and properly justified round-r pre-vote messages.
                if pre_votes.len() == self.threshold() {
                    // How many votes are 0?
                    let zero_count = pre_votes
                        .iter()
                        .filter(|(_, a)| a.value == PreVoteValue::Zero)
                        .count();

                    // How many votes are 1?
                    let one_count = pre_votes
                        .iter()
                        .filter(|(_, a)| a.value == PreVoteValue::One)
                        .count();

                    let (value, just) = if zero_count == self.threshold() {
                        decided_value = Some(false);
                        // If there are n − t pre-votes for 0:
                        //   - value: 0
                        //   - justification: combination of all pre-votes S-Signature shares
                        let sig_share: HashMap<&NodeId, &SignatureShare> =
                            pre_votes.iter().map(|(n, a)| (n, &a.sig_share)).collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        (
                            MainVoteValue::Zero,
                            MainVoteJustification::NoAbstainJustification(sig),
                        )
                    } else if one_count == self.threshold() {
                        decided_value = Some(true);
                        // If there are n − t pre-votes for 1:
                        //   - value: 1
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
                        //   - justification: justifications for the two conflicting pre-votes
                        let just_0 = pre_votes
                            .iter()
                            .filter(|(_k, v)| v.value == PreVoteValue::Zero)
                            .into_iter()
                            .last()
                            .unwrap()
                            .1
                            .justification
                            .clone();

                        let just_1 = pre_votes
                            .iter()
                            .filter(|(_k, v)| v.value == PreVoteValue::One)
                            .into_iter()
                            .last()
                            .unwrap()
                            .1
                            .justification
                            .clone();

                        (
                            MainVoteValue::Abstain,
                            MainVoteJustification::AbstainJustification(just_0, just_1),
                        )
                    };

                    // Produce an S-signature share on the message `(ID, main-vote, r, v)`
                    let sign_bytes = self.main_vote_bytes_to_sign(self.r, &value)?;
                    let sig_share = self.sec_key_share.sign(sign_bytes);

                    // send to all parties the message: `(ID, main-vote, r, v, justification, signature share)`
                    let main_vote_message = Message {
                        id: self.id.clone(),
                        action: Action::MainVote(MainVoteAction {
                            round: self.r,
                            value,
                            justification: just,
                            sig_share,
                        }),
                    };

                    self.broadcast(main_vote_message)?;
                    self.r += 1;
                    self.decided_value = decided_value;
                }
            }
        }

        Ok(())
    }

    pub fn is_decided(&self) -> bool {
        self.decided_value.is_some()
    }

    fn add_message(&mut self, sender: &NodeId, msg: &Message) -> Result<bool> {
        match &msg.action {
            Action::PreVote(action) => {
                let pre_votes = self.get_mut_pre_votes_by_round(action.round);
                if pre_votes.contains_key(sender) {
                    return Ok(false);
                }

                pre_votes.insert(*sender, action.clone());
            }
            Action::MainVote(action) => {
                let main_votes = self.get_mut_main_votes_by_round(action.round);
                if main_votes.contains_key(sender) {
                    return Ok(false);
                }

                main_votes.insert(*sender, action.clone());
            }
        }
        Ok(true)
    }

    fn check_message(&mut self, sender: &NodeId, msg: &Message) -> Result<()> {
        if msg.id != self.id {
            return Err(Error::InvalidMessage(format!(
                "invalid ID. expected: {}, got {}",
                self.id, msg.id
            )));
        }

        match &msg.action {
            Action::PreVote(action) => {
                // check the validity of the S-signature share on message (ID, pre-vote, r, b)
                let sign_bytes = self.pre_vote_bytes_to_sign(action.round, &action.value)?;
                if !self
                    .pub_key_set
                    .public_key_share(sender)
                    .verify(&action.sig_share, &sign_bytes)
                {
                    return Err(Error::InvalidMessage("invalid signature share".to_string()));
                }

                match &action.justification {
                    PreVoteJustification::RoundOneNoJustification => {
                        if action.round != 1 {
                            return Err(Error::InvalidMessage(format!(
                                "invalid round. expected 1, got {}",
                                action.round
                            )));
                        }
                    }
                    PreVoteJustification::RoundOneJustification(subject, proof) => {
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
                            .verify(proof, &subject.to_bytes())
                        {
                            return Err(Error::InvalidMessage("invalid proof".to_string()));
                        }

                        // A weaker validity: an honest party may only decide on a value
                        // for which it has the accompanying validating data.
                        if action.value != PreVoteValue::One {
                            return Err(Error::InvalidMessage("invalid value".to_string()));
                        }
                    }
                    PreVoteJustification::HardJustification(sig) => {
                        // Soft pre-vote justification is the S-threshold signature for `(ID, pre-vote, r − 1, b)`
                        let sign_bytes =
                            self.pre_vote_bytes_to_sign(action.round - 1, &action.value)?;
                        if !self.pub_key_set.public_key().verify(sig, &sign_bytes) {
                            return Err(Error::InvalidMessage(
                                "invalid hard-vote justification".to_string(),
                            ));
                        }
                    }
                    PreVoteJustification::SoftJustification(sig) => {
                        // Hard pre-vote justification is the S-threshold signature for `(ID, main-vote, r − 1, abstain)`
                        let sign_bytes =
                            self.main_vote_bytes_to_sign(self.r - 1, &MainVoteValue::Abstain)?;
                        if !self.pub_key_set.public_key().verify(sig, &sign_bytes) {
                            return Err(Error::InvalidMessage(
                                "invalid soft-vote justification".to_string(),
                            ));
                        }
                    }
                }
            }
            Action::MainVote(action) => {
                // check the validity of the S-signature share
                let sign_bytes = self.main_vote_bytes_to_sign(action.round, &action.value)?;
                if !self
                    .pub_key_set
                    .public_key_share(sender)
                    .verify(&action.sig_share, &sign_bytes)
                {
                    return Err(Error::InvalidMessage("invalid signature share".to_string()));
                }

                match &action.justification {
                    MainVoteJustification::NoAbstainJustification(sig) => {
                        // valid S-signature share on the message `(ID, pre-vote, r, b)`
                        let sign_bytes =
                            self.pre_vote_bytes_to_sign(action.round, &PreVoteValue::One)?;
                        if !self.pub_key_set.public_key().verify(sig, &sign_bytes) {
                            return Err(Error::InvalidMessage(
                                "invalid hard-vote justification".to_string(),
                            ));
                        }
                    }
                    MainVoteJustification::AbstainJustification(just_0, just_1) => {
                        match just_0 {
                            PreVoteJustification::RoundOneNoJustification => {}
                            _ => {
                                return Err(Error::InvalidMessage(format!(
                                    "invalid justification for value 0 in round 1: {:?}",
                                    just_0
                                )));
                            }
                        }

                        match just_1 {
                            PreVoteJustification::RoundOneJustification(subject, proof) => {
                                if !self
                                    .pub_key_set
                                    .public_key()
                                    .verify(proof, &subject.to_bytes())
                                {
                                    return Err(Error::InvalidMessage("invalid proof".to_string()));
                                }
                            }
                            _ => {
                                return Err(Error::InvalidMessage(format!(
                                    "invalid justification for value 0 in round 1: {:?}",
                                    just_1
                                )));
                            }
                        }
                    }
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

    // pre_vote_bytes_to_sign generates bytes for Pre-Vote signature share.
    // pre_vote_bytes_to_sign is same as serialized of $(ID, pre-vote, r, b)$ in spec.
    fn pre_vote_bytes_to_sign(&self, round: usize, v: &PreVoteValue) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(
            self.id.clone(),
            "pre-vote",
            round,
            v,
        ))?)
    }

    // main_vote_bytes_to_sign generates bytes for Main-Vote signature share.
    // main_vote_bytes_to_sign is same as serialized of $(ID, main-vote, r, v)$ in spec.
    fn main_vote_bytes_to_sign(&self, round: usize, v: &MainVoteValue) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(
            self.id.clone(),
            "main-vote",
            round,
            v,
        ))?)
    }

    // threshold return the threshold of the public key set.
    // It SHOULD be `n-t` according to the spec
    fn threshold(&self) -> usize {
        self.pub_key_set.threshold() + 1
    }

    /// returns the pre votes for the given `round`.
    /// If there is not votes for the `round`, it returns None.
    fn get_pre_votes_by_round(&self, round: usize) -> Option<&HashMap<NodeId, PreVoteAction>> {
        self.round_pre_votes.get(round - 1) // rounds start from 1 based on spec
    }

    /// returns the main votes for the given `round`.
    /// If there is not votes for the `round`, it returns None.
    fn get_main_votes_by_round(&self, round: usize) -> Option<&HashMap<NodeId, MainVoteAction>> {
        self.round_main_votes.get(round - 1) // rounds start from 1 based on spec
    }

    /// returns the pre votes for the given `round`.
    /// If there is not votes for the `round`, it expand the `round_pre_votes`.
    fn get_mut_pre_votes_by_round(&mut self, round: usize) -> &mut HashMap<NodeId, PreVoteAction> {
        // make sure we have the round messages
        while self.round_pre_votes.len() < round {
            self.round_pre_votes.push(HashMap::new());
        }
        self.round_pre_votes
            .get_mut(round - 1) // rounds start from 1 based on spec
            .unwrap()
    }

    /// returns the main votes for the given `round`.
    /// If there is not votes for the `round`, it expand the `round_main_votes`.
    fn get_mut_main_votes_by_round(
        &mut self,
        round: usize,
    ) -> &mut HashMap<NodeId, MainVoteAction> {
        // make sure we have the round messages
        while self.round_main_votes.len() < round {
            self.round_main_votes.push(HashMap::new());
        }

        self.round_main_votes
            .get_mut(round - 1) // rounds start from 1 based on spec
            .unwrap()
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
