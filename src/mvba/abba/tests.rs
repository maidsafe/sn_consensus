use super::{
    error::Error,
    message::{
        Action, MainVoteAction, MainVoteJustification, MainVoteValue, Message, PreVoteAction,
        PreVoteJustification, PreVoteValue,
    },
    Abba,
};
use crate::mvba::hash::Hash32;
use crate::mvba::{broadcaster::Broadcaster, NodeId};
use blsttc::{SecretKey, SecretKeySet};
use std::cell::RefCell;
use std::rc::Rc;

use rand::{random, thread_rng};

struct TestNet {
    sec_key_set: SecretKeySet,
    abba: Abba,
    proposal_digest: Hash32,
    c_final: crate::mvba::vcbc::message::Message,
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
        let proposal_digest = Hash32::calculate("test-data".as_bytes());
        let tag = crate::mvba::vcbc::message::Tag {
            id: "test-id".to_string(),
            j: i,
            s: 0,
        };
        let sign_bytes = crate::mvba::vcbc::c_ready_bytes_to_sign(&tag, proposal_digest).unwrap();
        let c_final_sig = sec_key_set.secret_key().sign(sign_bytes);
        let c_final = crate::mvba::vcbc::message::Message {
            tag: tag.clone(),
            action: crate::mvba::vcbc::message::Action::Final(proposal_digest, c_final_sig),
        };
        let broadcaster = Rc::new(RefCell::new(Broadcaster::new(
            random(),
            i,
            sec_key_share.clone(),
        )));
        let abba = Abba::new(
            "test".to_string(),
            i,
            tag,
            sec_key_set.public_keys(),
            sec_key_share,
            broadcaster.clone(),
        );

        Self {
            sec_key_set,
            abba,
            proposal_digest,
            c_final,
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
        let sign_bytes = self.abba.pre_vote_bytes_to_sign(round, &value).unwrap();
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
        let sign_bytes = self.abba.main_vote_bytes_to_sign(round, &value).unwrap();
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

    t.abba.pre_vote_one(t.c_final).unwrap();

    assert!(t.abba.get_pre_votes_by_round(1).unwrap().len() == 1);
    assert!(t.abba.get_pre_votes_by_round(2).is_none());
    assert!(t.abba.get_main_votes_by_round(2).is_none());
    assert!(t.abba.get_main_votes_by_round(2).is_none());
}

#[test]
fn test_should_publish_pre_vote_message() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba.pre_vote_one(t.c_final.clone()).unwrap();

    let just = PreVoteJustification::RoundOneJustification(t.c_final.clone());
    let pre_vote_x = t.make_pre_vote_msg(1, PreVoteValue::One, &just, &TestNet::PARTY_X);
    assert!(t.is_broadcasted(&pre_vote_x));
}

#[test]
fn test_should_publish_main_vote_message() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba.pre_vote_one(t.c_final.clone()).unwrap();
    let just = PreVoteJustification::RoundOneJustification(t.c_final.clone());

    let pre_vote_y = t.make_pre_vote_msg(1, PreVoteValue::One, &just, &TestNet::PARTY_Y);
    let pre_vote_s = t.make_pre_vote_msg(1, PreVoteValue::One, &just, &TestNet::PARTY_S);

    t.abba
        .receive_message(TestNet::PARTY_Y, pre_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, pre_vote_s)
        .unwrap();

    let sign_bytes = t
        .abba
        .pre_vote_bytes_to_sign(1, &PreVoteValue::One)
        .unwrap();
    let sig = t.sec_key_set.secret_key().sign(sign_bytes);
    let main_vote_just = MainVoteJustification::NoAbstainJustification(sig);
    let main_vote_x =
        t.make_main_vote_msg(1, MainVoteValue::One, &main_vote_just, &TestNet::PARTY_X);

    assert!(t.is_broadcasted(&main_vote_x));
}

#[test]
fn test_ignore_messages_with_wrong_id() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let just = PreVoteJustification::RoundOneJustification(t.c_final.clone());
    let mut pre_vote_x = t.make_pre_vote_msg(1, PreVoteValue::One, &just, &TestNet::PARTY_B);
    pre_vote_x.id = "another-id".to_string();

    let result = t.abba.receive_message(TestNet::PARTY_B, pre_vote_x);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == format!("invalid ID. expected: {}, got another-id", t.abba.id)));
}

#[test]
fn test_pre_vote_invalid_sig_share() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let just = PreVoteJustification::RoundOneJustification(t.c_final.clone());
    let invalid_sig_share = t
        .sec_key_set
        .secret_key_share(TestNet::PARTY_B)
        .sign("invalid-msg");
    let msg = Message {
        id: t.abba.id.clone(),
        action: Action::PreVote(PreVoteAction {
            round: 1,
            justification: just,
            value: PreVoteValue::One,
            sig_share: invalid_sig_share,
        }),
    };

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == "invalid signature share"));
}

#[test]
fn test_double_pre_vote() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let just_0 = PreVoteJustification::RoundOneNoJustification;
    let pre_vote_1 = t.make_pre_vote_msg(1, PreVoteValue::Zero, &just_0, &TestNet::PARTY_B);

    let just_1 = PreVoteJustification::RoundOneJustification(t.c_final.clone());
    let pre_vote_2 = t.make_pre_vote_msg(1, PreVoteValue::One, &just_1, &TestNet::PARTY_B);

    t.abba
        .receive_message(TestNet::PARTY_B, pre_vote_1.clone())
        .unwrap();

    // Repeating the message, should not return any error
    t.abba
        .receive_message(TestNet::PARTY_B, pre_vote_1)
        .unwrap();

    let result = t.abba.receive_message(TestNet::PARTY_B, pre_vote_2);
    println!("{:?}", result);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == format!(
            "double pre-vote detected from {:?}", &TestNet::PARTY_B)));
}

#[test]
fn test_pre_vote_round_1_invalid_round() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let just = PreVoteJustification::RoundOneJustification(t.c_final.clone());
    let msg = t.make_pre_vote_msg(2, PreVoteValue::One, &just, &TestNet::PARTY_B);

    t.abba
        .receive_message(TestNet::PARTY_B, msg)
        .expect_err("invalid round. expected 1, got 2");
}

#[test]
fn test_pre_vote_round_1_invalid_c_final_tag() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let mut invalid_c_final = t.c_final.clone();
    invalid_c_final.tag.id = "i-am-invalid".to_string();
    let just = PreVoteJustification::RoundOneJustification(invalid_c_final.clone());
    let pre_vote_x = t.make_pre_vote_msg(1, PreVoteValue::One, &just, &TestNet::PARTY_B);

    let result = t.abba.receive_message(TestNet::PARTY_B, pre_vote_x);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == format!("invalid tag. expected {:?}, got {:?}", t.abba.tag, invalid_c_final.tag)));
}
#[test]
fn test_pre_vote_round_1_invalid_c_final_signature() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let sign_bytes =
        crate::mvba::vcbc::c_ready_bytes_to_sign(&t.c_final.tag.clone(), t.proposal_digest)
            .unwrap();
    let invalid_sig = SecretKey::random().sign(sign_bytes);
    let invalid_c_final = crate::mvba::vcbc::message::Message {
        tag: t.c_final.tag.clone(),
        action: crate::mvba::vcbc::message::Action::Final(t.proposal_digest, invalid_sig),
    };
    let just = PreVoteJustification::RoundOneJustification(invalid_c_final);
    let msg = t.make_pre_vote_msg(1, PreVoteValue::One, &just, &TestNet::PARTY_B);

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
    if msg == "invalid signature for the VCBC proposal".to_string()));
}

#[test]
fn test_pre_vote_round_1_invalid_value_one() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let just = PreVoteJustification::RoundOneJustification(t.c_final.clone());
    let msg = t.make_pre_vote_msg(1, PreVoteValue::Zero, &just, &TestNet::PARTY_B);

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
    if msg == "initial value should be one"));
}

#[test]
fn test_pre_vote_round_1_invalid_value_zero() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    let just = PreVoteJustification::RoundOneNoJustification;
    let msg = t.make_pre_vote_msg(1, PreVoteValue::One, &just, &TestNet::PARTY_B);

    let result = t.abba.receive_message(TestNet::PARTY_B, msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
    if msg == "initial value should be zero"));
}

#[test]
fn test_normal_case_one_round() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba.pre_vote_one(t.c_final.clone()).unwrap();

    let pre_vote_just = PreVoteJustification::RoundOneJustification(t.c_final.clone());
    let pre_vote_y = t.make_pre_vote_msg(1, PreVoteValue::One, &pre_vote_just, &TestNet::PARTY_Y);
    let pre_vote_s = t.make_pre_vote_msg(1, PreVoteValue::One, &pre_vote_just, &TestNet::PARTY_S);

    t.abba
        .receive_message(TestNet::PARTY_Y, pre_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, pre_vote_s)
        .unwrap();

    let sign_bytes = t
        .abba
        .pre_vote_bytes_to_sign(1, &PreVoteValue::One)
        .unwrap();
    let sig = t.sec_key_set.secret_key().sign(sign_bytes);
    let main_vote_just = MainVoteJustification::NoAbstainJustification(sig);
    let main_vote_y =
        t.make_main_vote_msg(1, MainVoteValue::One, &main_vote_just, &TestNet::PARTY_Y);
    let main_vote_s =
        t.make_main_vote_msg(1, MainVoteValue::One, &main_vote_just, &TestNet::PARTY_S);

    t.abba
        .receive_message(TestNet::PARTY_Y, main_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, main_vote_s)
        .unwrap();

    assert!(t.abba.is_decided())
}

#[test]
fn test_normal_case_two_round() {
    let i = TestNet::PARTY_X;
    let mut t = TestNet::new(i);

    t.abba.pre_vote_one(t.c_final.clone()).unwrap();

    let round_1_just_0 = PreVoteJustification::RoundOneNoJustification;
    let round_1_just_1 = PreVoteJustification::RoundOneJustification(t.c_final.clone());

    let round_1_pre_vote_y =
        t.make_pre_vote_msg(1, PreVoteValue::One, &round_1_just_1, &TestNet::PARTY_Y);
    let round_1_pre_vote_s =
        t.make_pre_vote_msg(1, PreVoteValue::Zero, &round_1_just_0, &TestNet::PARTY_S);

    t.abba
        .receive_message(TestNet::PARTY_Y, round_1_pre_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, round_1_pre_vote_s)
        .unwrap();

    let round_1_main_vote_just =
        MainVoteJustification::AbstainJustification(round_1_just_0, round_1_just_1);
    let round_1_main_vote_x = t.make_main_vote_msg(
        1,
        MainVoteValue::Abstain,
        &round_1_main_vote_just,
        &TestNet::PARTY_X,
    );
    let round_1_main_vote_y = t.make_main_vote_msg(
        1,
        MainVoteValue::Abstain,
        &round_1_main_vote_just,
        &TestNet::PARTY_Y,
    );
    let round_1_main_vote_s = t.make_main_vote_msg(
        1,
        MainVoteValue::Abstain,
        &round_1_main_vote_just,
        &TestNet::PARTY_S,
    );
    assert!(t.is_broadcasted(&round_1_main_vote_x));

    t.abba
        .receive_message(TestNet::PARTY_Y, round_1_main_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, round_1_main_vote_s)
        .unwrap();

    // Round 2
    let sign_bytes = t
        .abba
        .main_vote_bytes_to_sign(1, &MainVoteValue::Abstain)
        .unwrap();
    let sig = t.sec_key_set.secret_key().sign(sign_bytes);
    let round_2_pre_vote_just = PreVoteJustification::SoftJustification(sig);

    let round_2_pre_vote_x = t.make_pre_vote_msg(
        2,
        PreVoteValue::One,
        &round_2_pre_vote_just,
        &TestNet::PARTY_X,
    );
    let round_2_pre_vote_y = t.make_pre_vote_msg(
        2,
        PreVoteValue::One,
        &round_2_pre_vote_just,
        &TestNet::PARTY_Y,
    );
    let round_2_pre_vote_s = t.make_pre_vote_msg(
        2,
        PreVoteValue::One,
        &round_2_pre_vote_just,
        &TestNet::PARTY_S,
    );

    assert!(t.is_broadcasted(&round_2_pre_vote_x));

    t.abba
        .receive_message(TestNet::PARTY_Y, round_2_pre_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, round_2_pre_vote_s)
        .unwrap();

    let sign_bytes = t
        .abba
        .pre_vote_bytes_to_sign(2, &PreVoteValue::One)
        .unwrap();
    let sig = t.sec_key_set.secret_key().sign(sign_bytes);
    let round_2_main_vote_just = MainVoteJustification::NoAbstainJustification(sig);
    let round_2_main_vote_x = t.make_main_vote_msg(
        2,
        MainVoteValue::One,
        &round_2_main_vote_just,
        &TestNet::PARTY_X,
    );
    let round_2_main_vote_y = t.make_main_vote_msg(
        2,
        MainVoteValue::One,
        &round_2_main_vote_just,
        &TestNet::PARTY_Y,
    );
    let round_2_main_vote_s = t.make_main_vote_msg(
        2,
        MainVoteValue::One,
        &round_2_main_vote_just,
        &TestNet::PARTY_S,
    );
    assert!(t.is_broadcasted(&round_2_main_vote_x));

    t.abba
        .receive_message(TestNet::PARTY_Y, round_2_main_vote_y)
        .unwrap();
    t.abba
        .receive_message(TestNet::PARTY_S, round_2_main_vote_s)
        .unwrap();

    assert!(t.abba.is_decided())
}
