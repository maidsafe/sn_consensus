// TODO: apply section 5.3.3. Further Optimizations

pub(super) mod message;

mod error;
use self::error::{Error, Result};
use self::message::{
    Action, MainVoteAction, MainVoteValue, Message, PreVoteAction, PreVoteJustification,
    PreVoteValue,
};
use super::vcbc::message::Tag;
use super::NodeId;
use crate::mvba::abba::message::MainVoteJustification;
use crate::mvba::broadcaster::Broadcaster;
use blsttc::{PublicKeySet, SecretKeyShare, SignatureShare};
use log::debug;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub(crate) const MODULE_NAME: &str = "abba";

/// The ABBA holds the information for Asynchronous Binary Byzantine Agreement protocol.
pub(crate) struct Abba {
    tag: Tag,                    // this takes the place of $ID$ in spec
    id: NodeId,                  // this is same as $i$ in spec
    round: usize,                // this is same as $r$ in spec
    decided_value: Option<bool>, // TODO: should be boolean?
    pub_key_set: PublicKeySet,
    sec_key_share: SecretKeyShare,
    broadcaster: Rc<RefCell<Broadcaster>>,
    round_pre_votes: Vec<HashMap<NodeId, PreVoteAction>>,
    round_main_votes: Vec<HashMap<NodeId, MainVoteAction>>,
}

impl Abba {
    pub fn new(
        tag: crate::mvba::vcbc::message::Tag,
        id: NodeId,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            tag,
            id,
            round: 1,
            decided_value: None,
            pub_key_set,
            sec_key_share,
            broadcaster,
            round_pre_votes: Vec::new(),
            round_main_votes: Vec::new(),
        }
    }

    /// pre_vote_zero starts the abba by broadcasting a pre-vote message with value 0.
    pub fn pre_vote_zero(&mut self) -> Result<()> {
        let justification = PreVoteJustification::FirstRoundZero;
        self.pre_vote(PreVoteValue::Zero, justification)
    }

    /// pre_vote_one starts the abba by broadcasting a pre-vote message with value 1.
    pub fn pre_vote_one(&mut self, c_final: crate::mvba::vcbc::message::Message) -> Result<()> {
        let justification = PreVoteJustification::FirstRoundOne(c_final);
        self.pre_vote(PreVoteValue::One, justification)
    }

    fn pre_vote(&mut self, value: PreVoteValue, justification: PreVoteJustification) -> Result<()> {
        // Produce an S-signature share on the message: (ID, pre-vote, r, b).
        let sign_bytes = self.pre_vote_bytes_to_sign(self.round, &value)?;
        let sig_share = self.sec_key_share.sign(sign_bytes);
        let action = PreVoteAction {
            round: self.round,
            value,
            justification,
            sig_share,
        };
        let msg = Message {
            tag: self.tag.clone(),
            action: Action::PreVote(Box::new(action)),
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
                if action.round + 1 != self.round {
                    return Ok(());
                }
                // 1. PRE-VOTE step.
                // Note: In weaker validity mode, round 1 comes with the external justification.

                // if r > 1, ...
                if self.round > 1 {
                    // select n − t properly justified main-votes from round r − 1
                    let main_votes = match self.get_main_votes_by_round(self.round - 1) {
                        Some(v) => v,
                        None => {
                            debug!("no main-votes for this round: {}", self.round);
                            return Ok(());
                        }
                    };

                    if main_votes.len() == self.threshold() {
                        let mut zero_votes = main_votes
                            .values()
                            .filter(|a| a.value == MainVoteValue::Zero);
                        let mut one_votes = main_votes
                            .values()
                            .filter(|a| a.value == MainVoteValue::One);
                        let abstain_votes = main_votes
                            .iter()
                            .filter(|(_, a)| a.value == MainVoteValue::Abstain);

                        // 3. CHECK FOR DECISION. Collect n −t valid and properly justified main-votes of round r .
                        // If these are all main-votes for b ∈ {0, 1}, then decide the value b for ID
                        let mut decided_value = None;
                        if zero_votes.clone().count() == self.threshold() {
                            decided_value = Some(false);
                        }

                        if one_votes.clone().count() == self.threshold() {
                            decided_value = Some(true);
                        }

                        let (value, justification) =
                            if let Some(zero_vote) = zero_votes.next() {
                                // if there is a main-vote for 0,
                                let sig =
                                    match &zero_vote.justification {
                                        MainVoteJustification::NoAbstain(sig) => sig,
                                        _ => return Err(Error::Generic(
                                            "protocol violated, invalid main-vote justification"
                                                .to_string(),
                                        )),
                                    };
                                // hard pre-vote for 0
                                (PreVoteValue::Zero, PreVoteJustification::Hard(sig.clone()))
                            } else if let Some(one_vote) = one_votes.next() {
                                // if there is a main-vote for 1,
                                let sig =
                                    match &one_vote.justification {
                                        MainVoteJustification::NoAbstain(sig) => sig,
                                        _ => return Err(Error::Generic(
                                            "protocol violated, invalid main-vote justification"
                                                .to_string(),
                                        )),
                                    };
                                // hard pre-vote for 1
                                (PreVoteValue::One, PreVoteJustification::Hard(sig.clone()))
                            } else if abstain_votes.clone().count() == self.threshold() {
                                // if all main-votes are abstain,
                                let sig_share: HashMap<&NodeId, &SignatureShare> =
                                    abstain_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                                let sig = self.pub_key_set.combine_signatures(sig_share)?;
                                // soft pre-vote for 1
                                // Coin value bias to 1 in weaker validity mode.
                                (PreVoteValue::One, PreVoteJustification::Soft(sig))
                            } else {
                                return Err(Error::Generic(
                                    "protocol violated, no pre-vote majority".to_string(),
                                ));
                            };

                        // Produce an S-signature share on the message `(ID, pre-vote, r, b)`
                        let sign_bytes = self.pre_vote_bytes_to_sign(self.round, &value)?;
                        let sig_share = self.sec_key_share.sign(sign_bytes);

                        // Send to all parties the message `(ID, pre-vote, r, b, justification, signature share)`
                        let pre_vote_message = Message {
                            tag: self.tag.clone(),
                            action: Action::PreVote(Box::new(PreVoteAction {
                                round: self.round,
                                value,
                                justification,
                                sig_share,
                            })),
                        };

                        self.broadcast(pre_vote_message)?;
                        self.decided_value = decided_value;
                    }
                }
            }

            Action::PreVote(action) => {
                if action.round != self.round {
                    return Ok(());
                }

                // 2. MAIN-VOTE. Collect n − t valid and properly justified round-r pre-vote messages.
                let pre_votes = match self.get_pre_votes_by_round(self.round) {
                    Some(v) => v,
                    None => {
                        debug!("no pre-votes for this round: {}", self.round);
                        return Ok(());
                    }
                };
                if pre_votes.len() == self.threshold() {
                    let zero_votes = pre_votes
                        .iter()
                        .filter(|(_, a)| a.value == PreVoteValue::Zero);

                    let one_votes = pre_votes
                        .iter()
                        .filter(|(_, a)| a.value == PreVoteValue::One);

                    let (value, just) = if zero_votes.clone().count() == self.threshold() {
                        // If there are n − t pre-votes for 0:
                        //   - value: 0
                        //   - justification: combination of all pre-votes S-Signature shares
                        let sig_share: HashMap<&NodeId, &SignatureShare> =
                            zero_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        (MainVoteValue::Zero, MainVoteJustification::NoAbstain(sig))
                    } else if one_votes.clone().count() == self.threshold() {
                        // If there are n − t pre-votes for 1:
                        //   - value: 1
                        //   - justification: combination of all pre-votes S-Signature shares
                        let sig_share: HashMap<&NodeId, &SignatureShare> =
                            one_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        (MainVoteValue::One, MainVoteJustification::NoAbstain(sig))
                    } else if let (Some(zero_vote), Some(one_vote)) = (
                        pre_votes.values().find(|a| a.value == PreVoteValue::Zero),
                        pre_votes.values().find(|a| a.value == PreVoteValue::One),
                    ) {
                        // there is a pre-vote for 0 and a pre-vote for 1 (conflicts):
                        //   - value:  abstain
                        //   - justification: justifications for the two conflicting pre-votes
                        let just_0 = zero_vote.justification.clone();
                        let just_1 = one_vote.justification.clone();

                        (
                            MainVoteValue::Abstain,
                            MainVoteJustification::Abstain(Box::new(just_0), Box::new(just_1)),
                        )
                    } else {
                        return Err(Error::Generic(
                            "protocol violated, no pre-vote majority".to_string(),
                        ));
                    };

                    // Produce an S-signature share on the message `(ID, main-vote, r, v)`
                    let sign_bytes = self.main_vote_bytes_to_sign(self.round, &value)?;
                    let sig_share = self.sec_key_share.sign(sign_bytes);

                    // send to all parties the message: `(ID, main-vote, r, v, justification, signature share)`
                    let main_vote_message = Message {
                        tag: self.tag.clone(),
                        action: Action::MainVote(Box::new(MainVoteAction {
                            round: self.round,
                            value,
                            justification: just,
                            sig_share,
                        })),
                    };

                    self.broadcast(main_vote_message)?;
                    self.round += 1;
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
                if let Some(exist) = pre_votes.get(sender) {
                    if exist != action.as_ref() {
                        return Err(Error::InvalidMessage(format!(
                            "double pre-vote detected from {:?}",
                            sender
                        )));
                    }
                    return Ok(false);
                }

                pre_votes.insert(*sender, *action.clone());
            }
            Action::MainVote(action) => {
                let main_votes = self.get_mut_main_votes_by_round(action.round);
                if let Some(exist) = main_votes.get(sender) {
                    if exist != action.as_ref() {
                        return Err(Error::InvalidMessage(format!(
                            "double main-vote detected from {:?}",
                            sender
                        )));
                    }
                    return Ok(false);
                }

                main_votes.insert(*sender, *action.clone());
            }
        }
        Ok(true)
    }

    fn check_message(&mut self, sender: &NodeId, msg: &Message) -> Result<()> {
        if msg.tag != self.tag {
            return Err(Error::InvalidMessage(format!(
                "invalid tag. expected: {:?}, got {:?}",
                self.tag, msg.tag
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
                    PreVoteJustification::FirstRoundZero => {
                        if action.round != 1 {
                            return Err(Error::InvalidMessage(format!(
                                "invalid round. expected 1, got {}",
                                action.round
                            )));
                        }

                        if action.value != PreVoteValue::Zero {
                            return Err(Error::InvalidMessage(
                                "initial value should be zero".to_string(),
                            ));
                        }
                    }
                    PreVoteJustification::FirstRoundOne(c_final) => {
                        if action.round != 1 {
                            return Err(Error::InvalidMessage(format!(
                                "invalid round. expected 1, got {}",
                                action.round
                            )));
                        }

                        if self.tag != c_final.tag {
                            return Err(Error::InvalidMessage(format!(
                                "invalid tag. expected {:?}, got {:?}",
                                self.tag, c_final.tag
                            )));
                        }

                        match &c_final.action {
                            crate::mvba::vcbc::message::Action::Final(digest, sig) => {
                                let sign_bytes = crate::mvba::vcbc::c_ready_bytes_to_sign(
                                    &c_final.tag,
                                    *digest,
                                )?;

                                if !self.pub_key_set.public_key().verify(sig, &sign_bytes) {
                                    return Err(Error::InvalidMessage(
                                        "invalid signature for the VCBC proposal".to_string(),
                                    ));
                                }
                            }
                            _ => {
                                return Err(Error::InvalidMessage(format!(
                                    "invalid action. expected c_final, got {:?}",
                                    c_final.action_str()
                                )));
                            }
                        }

                        // A weaker validity: an honest party may only decide on a value
                        // for which it has the accompanying validating data.
                        if action.value != PreVoteValue::One {
                            return Err(Error::InvalidMessage(
                                "initial value should be one".to_string(),
                            ));
                        }
                    }
                    PreVoteJustification::Hard(sig) => {
                        // Hard pre-vote justification is the S-threshold signature for `(ID, pre-vote, r − 1, b)`
                        let sign_bytes =
                            self.pre_vote_bytes_to_sign(action.round - 1, &action.value)?;
                        if !self.pub_key_set.public_key().verify(sig, &sign_bytes) {
                            return Err(Error::InvalidMessage(
                                "invalid hard-vote justification".to_string(),
                            ));
                        }
                    }
                    PreVoteJustification::Soft(sig) => {
                        // Soft pre-vote justification is the S-threshold signature for `(ID, main-vote, r − 1, abstain)`
                        let sign_bytes =
                            self.main_vote_bytes_to_sign(self.round - 1, &MainVoteValue::Abstain)?;
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
                    MainVoteJustification::NoAbstain(sig) => {
                        let pre_vote_value = if action.value == MainVoteValue::Zero {
                            PreVoteValue::Zero
                        } else if action.value == MainVoteValue::One {
                            PreVoteValue::One
                        } else {
                            return Err(Error::InvalidMessage(
                                "no-abstain justifications should come with no-abstain value"
                                    .to_string(),
                            ));
                        };
                        // valid S-signature share on the message `(ID, pre-vote, r, b)`
                        let sign_bytes =
                            self.pre_vote_bytes_to_sign(action.round, &pre_vote_value)?;
                        if !self.pub_key_set.public_key().verify(sig, &sign_bytes) {
                            return Err(Error::InvalidMessage(
                                "invalid main-vote justification".to_string(),
                            ));
                        }
                    }
                    MainVoteJustification::Abstain(just_0, just_1) => {
                        if action.value != MainVoteValue::Abstain {
                            return Err(Error::InvalidMessage(format!(
                                "abstain justifications should come with abstain value: {:?}",
                                action.value
                            )));
                        }
                        match just_0.as_ref() {
                            PreVoteJustification::FirstRoundZero => {}
                            _ => {
                                return Err(Error::InvalidMessage(format!(
                                    "invalid justification for value 0 in round 1: {:?}",
                                    just_0
                                )));
                            }
                        }

                        match just_1.as_ref() {
                            PreVoteJustification::FirstRoundOne(c_final) => match &c_final.action {
                                crate::mvba::vcbc::message::Action::Final(digest, sig) => {
                                    let sign_bytes = crate::mvba::vcbc::c_ready_bytes_to_sign(
                                        &c_final.tag,
                                        *digest,
                                    )?;

                                    if !self.pub_key_set.public_key().verify(sig, &sign_bytes) {
                                        return Err(Error::InvalidMessage(
                                            "invalid signature for the VCBC proposal".to_string(),
                                        ));
                                    }
                                }
                                _ => {
                                    return Err(Error::InvalidMessage(format!(
                                        "invalid action. expected c_final, got {:?}",
                                        c_final.action_str()
                                    )));
                                }
                            },
                            _ => {
                                return Err(Error::InvalidMessage(format!(
                                    "invalid justification for value 1 in round 1: {:?}",
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
        self.receive_message(self.id, msg)?;
        Ok(())
    }

    // pre_vote_bytes_to_sign generates bytes for Pre-Vote signature share.
    // pre_vote_bytes_to_sign is same as serialized of $(ID, pre-vote, r, b)$ in spec.
    fn pre_vote_bytes_to_sign(&self, round: usize, v: &PreVoteValue) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(&self.tag, "pre-vote", round, v))?)
    }

    // main_vote_bytes_to_sign generates bytes for Main-Vote signature share.
    // main_vote_bytes_to_sign is same as serialized of $(ID, main-vote, r, v)$ in spec.
    fn main_vote_bytes_to_sign(&self, round: usize, v: &MainVoteValue) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(&self.tag, "main-vote", round, v))?)
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
