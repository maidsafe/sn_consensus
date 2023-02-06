// TODO: apply section 5.3.3. Further Optimizations
pub(crate) mod error;
pub mod message;

use std::cell::RefCell;
use std::collections::HashMap;

use std::rc::Rc;

use blsttc::{PublicKeySet, SecretKeyShare, Signature, SignatureShare};

use self::error::{Error, Result};
use self::message::{
    Action, DecisionAction, MainVoteAction, MainVoteValue, Message, PreVoteAction,
    PreVoteJustification, Value,
};
use super::hash::Hash32;
use super::tag::Tag;
use super::NodeId;
use crate::mvba::abba::message::MainVoteJustification;
use crate::mvba::broadcaster::Broadcaster;

pub(crate) const MODULE_NAME: &str = "abba";

/// The ABBA holds the information for Asynchronous Binary Byzantine Agreement protocol.
pub(crate) struct Abba {
    tag: Tag,  // this is same as ID.j.s in the spec
    i: NodeId, // this is same as $i$ in spec
    r: usize,  // this is same as $r$ in spec
    voted: bool,
    weak_validity: Option<(Hash32, Signature)>,
    decided_value: Option<DecisionAction>,
    pub_key_set: PublicKeySet,
    sec_key_share: SecretKeyShare,
    broadcaster: Rc<RefCell<Broadcaster>>,
    round_pre_votes: Vec<HashMap<NodeId, PreVoteAction>>,
    round_main_votes: Vec<HashMap<NodeId, MainVoteAction>>,
}

impl Abba {
    pub fn new(
        tag: Tag,
        self_id: NodeId,
        pub_key_set: PublicKeySet,
        sec_key_share: SecretKeyShare,
        broadcaster: Rc<RefCell<Broadcaster>>,
    ) -> Self {
        Self {
            tag,
            i: self_id,
            r: 1,
            voted: false,
            weak_validity: None,
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
        self.pre_vote(Value::Zero, justification)
    }

    /// pre_vote_one starts the abba by broadcasting a pre-vote message with value 1.
    pub fn pre_vote_one(&mut self, digest: Hash32, sig: Signature) -> Result<()> {
        let justification = PreVoteJustification::WithValidity(digest, sig);
        self.pre_vote(Value::One, justification)
    }

    fn pre_vote(&mut self, value: Value, justification: PreVoteJustification) -> Result<()> {
        if self.voted {
            log::trace!("party {} voted before", self.i);
            return Ok(());
        }

        // Produce an S-signature share on the message: (ID, pre-vote, r, b).
        let sign_bytes = self.pre_vote_bytes_to_sign(1, &value)?;
        let sig_share = self.sec_key_share.sign(sign_bytes);

        // and send to all parties the message (ID, pre-process, Vi , signature share).
        let action = Action::PreVote(PreVoteAction {
            round: 1,
            value,
            justification,
            sig_share,
        });
        self.voted = true;
        self.broadcast(action)
    }

    // receive_message process the received message 'msg` from `initiator`
    pub fn receive_message(&mut self, initiator: NodeId, msg: Message) -> Result<()> {
        if self.decided_value.is_some() {
            // ignore the incoming messages if we have decided
            return Ok(());
        }

        log::trace!(
            "party {} received {} message: {:?} from {}",
            self.i,
            msg.action_str(),
            msg,
            initiator
        );

        self.check_message(&initiator, &msg)?;
        if !self.add_message(&initiator, &msg)? {
            return Ok(());
        }

        match &msg.action {
            Action::Decision(agg_main_vote) => {
                if let Some(existing_decision) = self.decided_value.as_ref() {
                    if existing_decision != agg_main_vote {
                        log::error!(
                            "party {}'s existing decision does not match the decision we received:
                            {existing_decision:?} != {agg_main_vote:?}",
                            self.i,
                        );

                        return Err(Error::Generic("received conflicting decision".into()));
                    }
                    return Ok(());
                }

                self.decided_value = Some(agg_main_vote.clone());
                self.broadcast(msg.action.clone())?; // re-broadcast the msg in case we were the only one who received it.
            }
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
                            log::debug!(
                                "party {} has no main-votes for this round: {}",
                                self.i,
                                self.r
                            );
                            return Ok(());
                        }
                    };
                    let mut zero_votes = main_votes
                        .iter()
                        .filter(|(_, a)| a.value == MainVoteValue::zero());
                    let mut one_votes = main_votes
                        .iter()
                        .filter(|(_, a)| a.value == MainVoteValue::one());
                    let abstain_votes = main_votes
                        .iter()
                        .filter(|(_, a)| a.value == MainVoteValue::Abstain);

                    // 3. CHECK FOR DECISION. Collect n −t valid and properly justified main-votes of round r .
                    if main_votes.len() >= self.threshold() {
                        // If these are all main-votes for b ∈ {0, 1}, then decide the value b for ID
                        if zero_votes.clone().count() >= self.threshold() {
                            log::info!(
                                "party {} decided for zero. tag={}, r={}",
                                self.i,
                                self.tag,
                                self.r
                            );
                            let sig_share: HashMap<&NodeId, &SignatureShare> =
                                zero_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                            let sig = self.pub_key_set.combine_signatures(sig_share)?;
                            let decision = DecisionAction {
                                round: action.round,
                                value: Value::Zero,
                                sig,
                            };
                            self.decided_value = Some(decision.clone());
                            self.broadcast(Action::Decision(decision))?;
                            return Ok(());
                        }

                        if one_votes.clone().count() >= self.threshold() {
                            log::info!(
                                "party {} decided for one. tag={}, r={}",
                                self.i,
                                self.tag,
                                self.r
                            );
                            let sig_share: HashMap<&NodeId, &SignatureShare> =
                                one_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                            let sig = self.pub_key_set.combine_signatures(sig_share)?;
                            let decision = DecisionAction {
                                round: action.round,
                                value: Value::One,
                                sig,
                            };
                            self.decided_value = Some(decision.clone());
                            self.broadcast(Action::Decision(decision))?;
                            return Ok(());
                        }

                        let (value, justification) = if let Some((digest, sig)) =
                            &self.weak_validity
                        {
                            if let Some(v) = self.get_pre_votes_by_round(self.r) {
                                if v.contains_key(&self.i) {
                                    log::debug!("party {} obtained the corresponding validating data after voting for zero", self.i);
                                    return Ok(());
                                }
                            };

                            // if all honest parties start with 0, they may still
                            // decide on 1 if they obtain the corresponding validating data
                            //  for 1 during the agreement protocol

                            (
                                Value::One,
                                PreVoteJustification::WithValidity(*digest, sig.clone()),
                            )
                        } else if let Some((_, zero_vote)) = zero_votes.next() {
                            // if there is a main-vote for 0,
                            let sig = match &zero_vote.justification {
                                MainVoteJustification::NoAbstain(sig) => sig,
                                _ => {
                                    return Err(Error::Generic(
                                        "protocol violated, invalid main-vote justification"
                                            .to_string(),
                                    ))
                                }
                            };
                            // hard pre-vote for 0
                            (Value::Zero, PreVoteJustification::Hard(sig.clone()))
                        } else if let Some((_, one_vote)) = one_votes.next() {
                            // if there is a main-vote for 1,
                            let sig = match &one_vote.justification {
                                MainVoteJustification::NoAbstain(sig) => sig,
                                _ => {
                                    return Err(Error::Generic(
                                        "protocol violated, invalid main-vote justification"
                                            .to_string(),
                                    ))
                                }
                            };
                            // hard pre-vote for 1
                            (Value::One, PreVoteJustification::Hard(sig.clone()))
                        } else if abstain_votes.clone().count() == main_votes.len() {
                            // if all main-votes are abstain,
                            let sig_share: HashMap<&NodeId, &SignatureShare> =
                                abstain_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                            let sig = self.pub_key_set.combine_signatures(sig_share)?;
                            // soft pre-vote for 1
                            // Coin value bias to 1 in weaker validity mode.
                            (Value::One, PreVoteJustification::Soft(sig))
                        } else {
                            return Err(Error::Generic(
                                "protocol violated, no pre-vote majority".to_string(),
                            ));
                        };

                        // Produce an S-signature share on the message `(ID, pre-vote, r, b)`
                        let sign_bytes = self.pre_vote_bytes_to_sign(self.r, &value)?;
                        let sig_share = self.sec_key_share.sign(sign_bytes);

                        // Send to all parties the message `(ID, pre-vote, r, b, justification, signature share)`
                        let action = Action::PreVote(PreVoteAction {
                            round: self.r,
                            value,
                            justification,
                            sig_share,
                        });
                        self.broadcast(action)?;
                    }
                }
            }

            Action::PreVote(action) => {
                if action.round != self.r {
                    return Ok(());
                }

                if let PreVoteJustification::WithValidity(digest, sig) = &action.justification {
                    self.weak_validity = Some((*digest, sig.clone()));
                };

                // 2. MAIN-VOTE. Collect n − t valid and properly justified round-r pre-vote messages.
                let pre_votes = match self.get_pre_votes_by_round(self.r) {
                    Some(v) => v,
                    None => {
                        log::debug!(
                            "party {} has no pre-votes for this round: {}",
                            self.i,
                            self.r
                        );
                        return Ok(());
                    }
                };
                if pre_votes.len() >= self.threshold() {
                    let zero_votes = pre_votes.iter().filter(|(_, a)| a.value == Value::Zero);
                    let one_votes = pre_votes.iter().filter(|(_, a)| a.value == Value::One);

                    let (value, just) = if zero_votes.clone().count() == pre_votes.len() {
                        // If there are n − t pre-votes for 0:
                        //   - value: 0
                        //   - justification: combination of all pre-votes S-Signature shares
                        let sig_share: HashMap<&NodeId, &SignatureShare> =
                            zero_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        (MainVoteValue::zero(), MainVoteJustification::NoAbstain(sig))
                    } else if one_votes.clone().count() == pre_votes.len() {
                        // If there are n − t pre-votes for 1:
                        //   - value: 1
                        //   - justification: combination of all pre-votes S-Signature shares
                        let sig_share: HashMap<&NodeId, &SignatureShare> =
                            one_votes.map(|(n, a)| (n, &a.sig_share)).collect();
                        let sig = self.pub_key_set.combine_signatures(sig_share)?;

                        (MainVoteValue::one(), MainVoteJustification::NoAbstain(sig))
                    } else if let (Some(zero_vote), Some(one_vote)) = (
                        pre_votes.values().find(|a| a.value == Value::Zero),
                        pre_votes.values().find(|a| a.value == Value::One),
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
                    let sign_bytes = self.main_vote_bytes_to_sign(self.r, &value)?;
                    let sig_share = self.sec_key_share.sign(sign_bytes);

                    // send to all parties the message: `(ID, main-vote, r, v, justification, signature share)`
                    let action = Action::MainVote(MainVoteAction {
                        round: self.r,
                        value,
                        justification: just,
                        sig_share,
                    });
                    self.broadcast(action)?;
                    self.r += 1;
                }
            }
        }

        Ok(())
    }

    pub fn decided_value(&self) -> Option<bool> {
        match &self.decided_value {
            Some(v) => match v.value {
                Value::One => Some(true),
                Value::Zero => Some(false),
            },
            None => None,
        }
    }

    fn add_message(&mut self, initiator: &NodeId, msg: &Message) -> Result<bool> {
        match &msg.action {
            Action::PreVote(action) => {
                let pre_votes = self.get_mut_pre_votes_by_round(action.round)?;
                if let Some(exist) = pre_votes.get(initiator) {
                    if exist != action {
                        return Err(Error::InvalidMessage(format!(
                            "double pre-vote detected from {initiator:?}"
                        )));
                    }
                    return Ok(false);
                }

                pre_votes.insert(*initiator, action.clone());
            }
            Action::MainVote(action) => {
                let main_votes = self.get_mut_main_votes_by_round(action.round)?;
                if let Some(exist) = main_votes.get(initiator) {
                    if exist != action {
                        return Err(Error::InvalidMessage(format!(
                            "double main-vote detected from {initiator:?}"
                        )));
                    }
                    return Ok(false);
                }

                main_votes.insert(*initiator, action.clone());
            }
            Action::Decision(_action) => (),
        }
        Ok(true)
    }

    fn check_message(&self, initiator: &NodeId, msg: &Message) -> Result<()> {
        if msg.tag != self.tag {
            return Err(Error::InvalidMessage(format!(
                "invalid tag. expected: {}, got {}",
                self.tag, msg.tag
            )));
        }

        match &msg.action {
            Action::PreVote(action) => {
                // check the validity of the S-signature share on message (ID, pre-vote, r, b)
                let sign_bytes = self.pre_vote_bytes_to_sign(action.round, &action.value)?;
                if !self
                    .pub_key_set
                    .public_key_share(initiator)
                    .verify(&action.sig_share, sign_bytes)
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

                        if action.value != Value::Zero {
                            return Err(Error::InvalidMessage(
                                "initial value should be zero".to_string(),
                            ));
                        }
                    }
                    PreVoteJustification::WithValidity(digest, sig) => {
                        let sign_bytes =
                            crate::mvba::vcbc::c_ready_bytes_to_sign(&self.tag, digest)?;

                        if !self.pub_key_set.public_key().verify(sig, sign_bytes) {
                            return Err(Error::InvalidMessage(
                                "invalid signature for the VCBC proposal".to_string(),
                            ));
                        }

                        // A weaker validity: an honest party may only decide on a value
                        // for which it has the accompanying validating data.
                        if action.value != Value::One {
                            return Err(Error::InvalidMessage(
                                "initial value should be one".to_string(),
                            ));
                        }
                    }
                    PreVoteJustification::Hard(sig) => {
                        // Hard pre-vote justification is the S-threshold signature for `(ID, pre-vote, r − 1, b)`
                        let sign_bytes =
                            self.pre_vote_bytes_to_sign(action.round - 1, &action.value)?;
                        if !self.pub_key_set.public_key().verify(sig, sign_bytes) {
                            return Err(Error::InvalidMessage(
                                "invalid hard-vote justification".to_string(),
                            ));
                        }
                    }
                    PreVoteJustification::Soft(sig) => {
                        // Soft pre-vote justification is the S-threshold signature for `(ID, main-vote, r − 1, abstain)`
                        let sign_bytes = self
                            .main_vote_bytes_to_sign(action.round - 1, &MainVoteValue::Abstain)?;
                        if !self.pub_key_set.public_key().verify(sig, sign_bytes) {
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
                    .public_key_share(initiator)
                    .verify(&action.sig_share, sign_bytes)
                {
                    return Err(Error::InvalidMessage("invalid signature share".to_string()));
                }

                match &action.justification {
                    MainVoteJustification::NoAbstain(sig) => {
                        let pre_vote_value = if let MainVoteValue::Value(value) = action.value {
                            value
                        } else {
                            return Err(Error::InvalidMessage(
                                "no-abstain justifications should come with no-abstain value"
                                    .to_string(),
                            ));
                        };
                        // valid S-signature share on the message `(ID, pre-vote, r, b)`
                        let sign_bytes =
                            self.pre_vote_bytes_to_sign(action.round, &pre_vote_value)?;
                        if !self.pub_key_set.public_key().verify(sig, sign_bytes) {
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
                            PreVoteJustification::Hard(sig) => {
                                let sign_bytes =
                                    self.pre_vote_bytes_to_sign(action.round - 1, &Value::Zero)?;
                                if !self.pub_key_set.public_key().verify(sig, sign_bytes) {
                                    return Err(Error::InvalidMessage(
                                        "invalid abstain justification for value zero".to_string(),
                                    ));
                                }
                            }
                            _ => {
                                return Err(Error::InvalidMessage(format!(
                                    "invalid justification for value 0 in round 1: {just_0:?}"
                                )));
                            }
                        }

                        match just_1.as_ref() {
                            PreVoteJustification::WithValidity(digest, sig) => {
                                let sign_bytes =
                                    crate::mvba::vcbc::c_ready_bytes_to_sign(&self.tag, digest)?;

                                if !self.pub_key_set.public_key().verify(sig, sign_bytes) {
                                    return Err(Error::InvalidMessage(
                                        "invalid signature for the VCBC proposal".to_string(),
                                    ));
                                }
                            }
                            _ => {
                                return Err(Error::InvalidMessage(format!(
                                    "invalid justification for value 1 in round 1: {just_1:?}"
                                )));
                            }
                        }
                    }
                }
            }
            Action::Decision(action) => {
                // check the validity of the S-signature share
                let sign_bytes = self
                    .main_vote_bytes_to_sign(action.round, &MainVoteValue::Value(action.value))?;
                if !self
                    .pub_key_set
                    .public_key()
                    .verify(&action.sig, sign_bytes)
                {
                    return Err(Error::InvalidMessage("invalid signature".to_string()));
                }
            }
        }

        Ok(())
    }

    // broadcast sends the message `msg` to all other peers in the network.
    // It adds the message to our messages log.
    fn broadcast(&mut self, action: Action) -> Result<()> {
        log::debug!("party {} broadcasts {action:?}", self.i);

        let msg = Message {
            tag: self.tag.clone(),
            action,
        };
        let data = bincode::serialize(&msg)?;
        self.broadcaster
            .borrow_mut()
            .broadcast(MODULE_NAME, Some(self.tag.proposer), data);
        self.receive_message(self.i, msg)?;
        Ok(())
    }

    // pre_vote_bytes_to_sign generates bytes for Pre-Vote signature share.
    // pre_vote_bytes_to_sign is same as serialized of $(ID, pre-vote, r, b)$ in spec.
    fn pre_vote_bytes_to_sign(&self, round: usize, v: &Value) -> Result<Vec<u8>> {
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
    fn get_mut_pre_votes_by_round(
        &mut self,
        round: usize,
    ) -> Result<&mut HashMap<NodeId, PreVoteAction>> {
        // make sure we have the round messages
        while self.round_pre_votes.len() < round {
            self.round_pre_votes.push(HashMap::new());
        }

        // rounds start from 1 based on spec
        match self.round_pre_votes.get_mut(round - 1) {
            Some(v) => Ok(v),
            None => Err(Error::Generic(format!(
                "round_pre_votes is not initialized for round {round}"
            ))),
        }
    }

    /// returns the main votes for the given `round`.
    /// If there is not votes for the `round`, it expand the `round_main_votes`.
    fn get_mut_main_votes_by_round(
        &mut self,
        round: usize,
    ) -> Result<&mut HashMap<NodeId, MainVoteAction>> {
        // make sure we have the round messages
        while self.round_main_votes.len() < round {
            self.round_main_votes.push(HashMap::new());
        }

        // rounds start from 1 based on spec
        match self.round_main_votes.get_mut(round - 1) {
            Some(v) => Ok(v),
            None => Err(Error::Generic(format!(
                "round_main_votes is not initialized for round {round}"
            ))),
        }
    }
}

#[cfg(test)]
#[path = "./tests.rs"]
mod tests;
