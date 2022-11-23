use super::{
    error::Error,
    message::{
        Action, MainVoteAction, MainVoteJustification, MainVoteValue, Message, PreVoteAction,
        PreVoteJustification, PreVoteValue,
    },
    Abba,
};
use crate::mvba::bundle::Bundle;
use crate::mvba::hash::Hash32;
use crate::mvba::{broadcaster::Broadcaster, NodeId};
use blsttc::{SecretKey, SecretKeySet, Signature, SignatureShare};
use quickcheck_macros::quickcheck;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::{cell::RefCell, fmt::format};

use rand::{random, thread_rng, Rng};

struct TestNet {
    sec_key_set: SecretKeySet,
    abba: Abba,
    subject_sig: Signature,
    broadcaster: Rc<RefCell<Broadcaster>>,
}

impl TestNet {
    const PARTY_X: NodeId = 0;
    const PARTY_Y: NodeId = 1;
    const PARTY_B: NodeId = 2;
    const PARTY_S: NodeId = 3;

    // There are 4 parties: X, Y, B, S (B is Byzantine and S is Slow)
    // The ABBA test instance creates for party `i`, `ID` sets to `test`
    pub fn new(i: NodeId) -> Self {
        let mut rng = thread_rng();
        let sec_key_set = SecretKeySet::random(2, &mut rng);
        let sec_key_share = sec_key_set.secret_key_share(i);
        let subject = Hash32::calculate("test-data".as_bytes());
        let subject_sig = sec_key_set.secret_key().sign(subject.to_bytes());
        let broadcaster = Rc::new(RefCell::new(Broadcaster::new(
            random(),
            i,
            sec_key_share.clone(),
        )));
        let abba = Abba::new(
            "test".to_string(),
            i,
            subject,
            sec_key_set.public_keys(),
            sec_key_share,
            broadcaster.clone(),
        );

        Self {
            sec_key_set,
            abba,
            subject_sig,
            broadcaster,
        }
    }

    pub fn make_pre_vote_msg(
        &self,
        round: usize,
        value: PreVoteValue,
        justification: &PreVoteJustification,
        peer_id: &NodeId,
    ) -> Message {
        let sign_bytes = self.abba.pre_vote_bytes_to_sign(&round, &value).unwrap();
        let sig_share = self.sec_key_set.secret_key_share(peer_id).sign(sign_bytes);
        Message {
            id: self.abba.id.clone(),
            action: Action::PreVote(PreVoteAction {
                round,
                value,
                justification: justification.clone(),
                sig_share,
            }),
        }
    }

    pub fn make_main_vote_msg(
        &self,
        round: usize,
        value: MainVoteValue,
        justification: &MainVoteJustification,
        peer_id: &NodeId,
    ) -> Message {
        let sign_bytes = self.abba.main_vote_bytes_to_sign(&round, &value).unwrap();
        let sig_share = self.sec_key_set.secret_key_share(peer_id).sign(sign_bytes);
        Message {
            id: self.abba.id.clone(),
            action: Action::MainVote(MainVoteAction {
                round,
                value,
                justification: justification.clone(),
                sig_share,
            }),
        }
    }

    pub fn is_broadcasted(&self, msg: &Message) -> bool {
        self.broadcaster
            .borrow()
            .has_broadcast_message(&bincode::serialize(msg).unwrap())
    }
}

#[test]
fn test_round_votes() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba.pre_vote(PreVoteValue::One, t.subject_sig).unwrap();

    assert!(t.abba.get_pre_votes_by_round(1).unwrap().len() == 1);
    assert!(t.abba.get_pre_votes_by_round(2).is_none());
    assert!(t.abba.get_main_votes_by_round(2).is_none());
    assert!(t.abba.get_main_votes_by_round(2).is_none());
}

#[test]
fn test_should_publish_pre_vote_message() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba
        .pre_vote(PreVoteValue::One, t.subject_sig.clone())
        .unwrap();

    let justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), t.subject_sig.clone());
    let pre_vote_x = t.make_pre_vote_msg(1, PreVoteValue::One, &justification, &TestNet::PARTY_X);
    assert!(t.is_broadcasted(&pre_vote_x));
}

#[test]
fn test_should_publish_main_vote_message() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba
        .pre_vote(PreVoteValue::One, t.subject_sig.clone())
        .unwrap();
    let justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), t.subject_sig.clone());

    let pre_vote_msg_y =
        t.make_pre_vote_msg(1, PreVoteValue::One, &justification, &TestNet::PARTY_Y);
    let pre_vote_msg_s =
        t.make_pre_vote_msg(1, PreVoteValue::One, &justification, &TestNet::PARTY_S);

    t.abba
        .receive_message(TestNet::PARTY_Y, pre_vote_msg_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, pre_vote_msg_s)
        .unwrap();

    let sign_bytes = t
        .abba
        .pre_vote_bytes_to_sign(&1, &PreVoteValue::One)
        .unwrap();
    let sig = t.sec_key_set.secret_key().sign(sign_bytes);
    let main_vote_justification = MainVoteJustification::NoAbstainJustification(sig);

    let main_vote_msg = t.make_main_vote_msg(1, MainVoteValue::One, &main_vote_justification, &i);
    assert!(t.is_broadcasted(&main_vote_msg));
}

#[test]
fn test_ignore_messages_with_wrong_id() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), t.subject_sig.clone());
    let mut msg = t.make_pre_vote_msg(1, PreVoteValue::One, &justification, &TestNet::PARTY_B);
    msg.id = "another-id".to_string();

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == format!("invalid ID. expected: {}, got another-id", t.abba.id)));
}

#[test]
fn test_pre_vote_invalid_sig_share() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), t.subject_sig.clone());
    let invalid_sig_share = t
        .sec_key_set
        .secret_key_share(TestNet::PARTY_B)
        .sign("invalid-msg");
    let msg = Message {
        id: t.abba.id.clone(),
        action: Action::PreVote(PreVoteAction {
            round: 1,
            justification: justification,
            value: PreVoteValue::One,
            sig_share: invalid_sig_share,
        }),
    };

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == "invalid signature share"));
}

#[test]
fn test_pre_vote_round_1_invalid_round() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), t.subject_sig.clone());
    let msg = t.make_pre_vote_msg(2, PreVoteValue::One, &justification, &TestNet::PARTY_B);

    t.abba
        .receive_message(TestNet::PARTY_B, msg)
        .expect_err("invalid round. expected 1, got 2");
}

#[test]
fn test_pre_vote_round_1_invalid_subject() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let unknown_subject = Hash32::calculate("unknown-subject".as_bytes());
    let justification =
        PreVoteJustification::RoundOneJustification(unknown_subject.clone(), t.subject_sig.clone());
    let msg = t.make_pre_vote_msg(1, PreVoteValue::One, &justification, &TestNet::PARTY_B);

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
    if msg == format!(
        "invalid subject. expected {}, got {}",
        t.abba.subject, unknown_subject
    )));
}

#[test]
fn test_pre_vote_round_1_invalid_proof() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let invalid_proof = SecretKey::random().sign(t.abba.subject.to_bytes());
    let justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), invalid_proof);
    let msg = t.make_pre_vote_msg(1, PreVoteValue::One, &justification, &TestNet::PARTY_B);

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
    if msg == format!(
        "invalid proof",
    )));
}

#[test]
fn test_pre_vote_round_1_invalid_value() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), t.subject_sig.clone());
    let msg = t.make_pre_vote_msg(1, PreVoteValue::Zero, &justification, &TestNet::PARTY_B);

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
    if msg == format!(
        "invalid value",
    )));
}

#[test]
fn test_normal_case() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba
        .pre_vote(PreVoteValue::One, t.subject_sig.clone())
        .unwrap();

    let pre_vote_justification =
        PreVoteJustification::RoundOneJustification(t.abba.subject.clone(), t.subject_sig.clone());
    let pre_vote_y = t.make_pre_vote_msg(
        1,
        PreVoteValue::One,
        &pre_vote_justification,
        &TestNet::PARTY_Y,
    );
    let pre_vote_s = t.make_pre_vote_msg(
        1,
        PreVoteValue::One,
        &pre_vote_justification,
        &TestNet::PARTY_S,
    );

    let sign_bytes = t
        .abba
        .pre_vote_bytes_to_sign(&1, &PreVoteValue::One)
        .unwrap();
    let sig = t.sec_key_set.secret_key().sign(sign_bytes);
    let main_vote_justification = MainVoteJustification::NoAbstainJustification(sig);
    t.abba
        .receive_message(TestNet::PARTY_Y, pre_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, pre_vote_s)
        .unwrap();

    let main_vote_x = t.make_main_vote_msg(
        1,
        MainVoteValue::One,
        &main_vote_justification,
        &TestNet::PARTY_Y,
    );
    let main_vote_s = t.make_main_vote_msg(
        1,
        MainVoteValue::One,
        &main_vote_justification,
        &TestNet::PARTY_S,
    );

    t.abba
        .receive_message(TestNet::PARTY_Y, main_vote_x)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, main_vote_s)
        .unwrap();

    assert!(t.abba.decided)
}
