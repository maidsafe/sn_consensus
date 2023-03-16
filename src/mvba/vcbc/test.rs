use super::message::{Action, Message};
use super::Error;
use super::{NodeId, Vcbc};
use crate::mvba::broadcaster::Broadcaster;

use crate::mvba::bundle;
use crate::mvba::hash::Hash32;
use crate::mvba::tag::{Domain, Tag};
use crate::mvba::vcbc::c_ready_bytes_to_sign;
use blsttc::{SecretKeySet, Signature, SignatureShare};

use rand::{thread_rng, Rng};

fn valid_proposal(_: NodeId, _: &Vec<u8>) -> bool {
    true
}

fn invalid_proposal(_: NodeId, _: &Vec<u8>) -> bool {
    false
}

struct TestNet {
    sec_key_set: SecretKeySet,
    vcbc: Vcbc<Vec<u8>>,
    m: Vec<u8>,
    broadcaster: Broadcaster<Vec<u8>>,
}

impl TestNet {
    const PARTY_X: NodeId = 0;
    const PARTY_Y: NodeId = 1;
    const PARTY_B: NodeId = 2;
    const PARTY_S: NodeId = 3;

    // There are 4 parties: X, Y, B, S (B is Byzantine and S is Slow)
    // The VCBC test instance creates for party `i` with `ID` sets to `test-id`
    // and `s` sets to `0`.
    pub fn new(i: NodeId, j: NodeId) -> Self {
        let mut rng = thread_rng();
        let sec_key_set = SecretKeySet::random(2, &mut rng);
        let sec_key_share = sec_key_set.secret_key_share(i);
        let broadcaster = Broadcaster::new(i);
        let tag = Tag::new(Domain::new("test-domain", 0), j);
        let vcbc = Vcbc::new(
            tag,
            i,
            sec_key_set.public_keys(),
            sec_key_share,
            valid_proposal,
        );

        // Creating a random proposal
        let m = (0..100).map(|_| rng.gen_range(0..64)).collect();

        Self {
            sec_key_set,
            vcbc,
            m,
            broadcaster,
        }
    }

    pub fn make_send_msg(&self, m: &[u8]) -> Message<Vec<u8>> {
        Message {
            tag: self.vcbc.tag.clone(),
            action: Action::Send(m.to_vec()),
        }
    }

    pub fn make_ready_msg(&self, d: &Hash32, peer_id: &NodeId) -> Message<Vec<u8>> {
        let sig_share = self.sig_share(d, peer_id);
        Message {
            tag: self.vcbc.tag.clone(),
            action: Action::Ready(*d, sig_share),
        }
    }

    pub fn make_final_msg(&self, d: &Hash32) -> Message<Vec<u8>> {
        Message {
            tag: self.vcbc.tag.clone(),
            action: Action::Final(*d, self.u()),
        }
    }

    pub fn is_broadcasted(&self, msg: &Message<Vec<u8>>) -> bool {
        self.broadcaster
            .has_gossip_message(&bundle::Message::Vcbc(msg.clone()))
    }

    pub fn is_send_to(&self, to: &NodeId, msg: &Message<Vec<u8>>) -> bool {
        self.broadcaster
            .has_direct_message(to, &bundle::Message::Vcbc(msg.clone()))
    }

    // m is same as proposal
    pub fn m(&self) -> Vec<u8> {
        self.m.clone()
    }

    // d is same as proposal's digest
    pub fn d(&self) -> Hash32 {
        Hash32::calculate(&self.m).unwrap()
    }

    // u is same as final signature
    pub fn u(&self) -> Signature {
        let sign_bytes = c_ready_bytes_to_sign(&self.vcbc.tag, &self.d()).unwrap();
        self.sec_key_set.secret_key().sign(sign_bytes)
    }

    fn sig_share(&self, digest: &Hash32, id: &NodeId) -> SignatureShare {
        let sign_bytes = c_ready_bytes_to_sign(&self.vcbc.tag, digest).unwrap();
        let sec_key_share = self.sec_key_set.secret_key_share(id);

        sec_key_share.sign(sign_bytes)
    }
}

#[test]
fn test_ignore_messages_with_invalid_tag() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_X;
    let mut t = TestNet::new(i, j);

    let mut final_msg = t.make_final_msg(&t.d());
    final_msg.tag.domain = Domain::new("another-domain", 0);

    let result = t
        .vcbc
        .receive_message(TestNet::PARTY_B, final_msg, &mut t.broadcaster);
    match result {
        Err(Error::InvalidMessage(msg)) => assert_eq!(
            msg,
            "invalid tag. expected test-domain[0].0, got another-domain[0].0"
        ),
        res => panic!("Unexpected result: {res:?}"),
    }
}

#[test]
fn test_invalid_message() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_B;
    let mut t = TestNet::new(i, j);
    t.vcbc.message_validity = invalid_proposal;

    let msg = t.make_send_msg(&t.m);

    let result = t
        .vcbc
        .receive_message(TestNet::PARTY_B, msg, &mut t.broadcaster);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
    if msg == *"invalid proposal"));
}

#[test]
fn test_should_c_send() {
    let i = TestNet::PARTY_S;
    let j = TestNet::PARTY_S; // i and j are same
    let mut t = TestNet::new(i, j);

    t.vcbc.c_broadcast(t.m.clone(), &mut t.broadcaster).unwrap();

    let send_msg = t.make_send_msg(&t.m());
    assert!(t.is_broadcasted(&send_msg));
}

#[test]
fn test_should_c_ready() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_S;
    let mut t = TestNet::new(i, j);

    let send_msg = t.make_send_msg(&t.m());
    t.vcbc
        .receive_message(j, send_msg, &mut t.broadcaster)
        .unwrap();

    let ready_msg_x = t.make_ready_msg(&t.d(), &i);
    assert!(t.is_send_to(&j, &ready_msg_x));
}

#[test]
fn test_normal_case_operation() {
    let i = TestNet::PARTY_S;
    let j = TestNet::PARTY_S; // i and j are same
    let mut t = TestNet::new(i, j);

    t.vcbc.c_broadcast(t.m.clone(), &mut t.broadcaster).unwrap();

    let ready_msg_x = t.make_ready_msg(&t.d(), &TestNet::PARTY_X);
    let ready_msg_y = t.make_ready_msg(&t.d(), &TestNet::PARTY_Y);

    t.vcbc
        .receive_message(TestNet::PARTY_X, ready_msg_x, &mut t.broadcaster)
        .unwrap();
    t.vcbc
        .receive_message(TestNet::PARTY_Y, ready_msg_y, &mut t.broadcaster)
        .unwrap();

    assert!(t.vcbc.read_delivered().is_some());
}

#[test]
fn test_final_message_first() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_S;
    let mut t = TestNet::new(i, j);

    let send_msg = t.make_send_msg(&t.m());
    let final_msg = t.make_final_msg(&t.d());

    t.vcbc
        .receive_message(TestNet::PARTY_S, final_msg, &mut t.broadcaster)
        .unwrap();
    t.vcbc
        .receive_message(TestNet::PARTY_S, send_msg, &mut t.broadcaster)
        .unwrap();

    assert!(t.vcbc.read_delivered().is_some());
}

#[test]
fn test_request_for_proposal() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_S;
    let mut t = TestNet::new(i, j);

    let final_msg = t.make_final_msg(&t.d());
    let request_msg = Message {
        tag: t.vcbc.tag.clone(),
        action: Action::Request,
    };

    t.vcbc
        .receive_message(TestNet::PARTY_S, final_msg, &mut t.broadcaster)
        .unwrap();
    assert!(t.is_send_to(&TestNet::PARTY_S, &request_msg));
}

#[test]
fn test_invalid_digest() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_X;
    let mut t = TestNet::new(i, j);

    t.vcbc.c_broadcast(t.m.clone(), &mut t.broadcaster).unwrap();

    let invalid_digest = Hash32::calculate("invalid-data").unwrap();
    let ready_msg_x = t.make_ready_msg(&invalid_digest, &i);
    assert!(t
        .vcbc
        .receive_message(TestNet::PARTY_B, ready_msg_x, &mut t.broadcaster)
        .is_err());
}

#[test]
fn test_invalid_sig_share() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_X;
    let mut t = TestNet::new(i, j);

    t.vcbc.c_broadcast(t.m.clone(), &mut t.broadcaster).unwrap();

    let sig_share = t
        .sec_key_set
        .secret_key_share(TestNet::PARTY_B)
        .sign("invalid_message".as_bytes());
    let ready_msg_x = Message {
        tag: t.vcbc.tag.clone(),
        action: Action::Ready(t.d(), sig_share),
    };

    t.vcbc
        .receive_message(TestNet::PARTY_B, ready_msg_x, &mut t.broadcaster)
        .unwrap();

    assert!(!t.vcbc.wd.contains_key(&TestNet::PARTY_B));
}

#[test]
fn test_c_request() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_X;
    let mut t = TestNet::new(i, j);

    let sig = t.sec_key_set.secret_key().sign(t.m());

    t.vcbc.m_bar = Some(t.m());
    t.vcbc.u_bar = Some(sig.clone());

    let request_msg = Message {
        tag: t.vcbc.tag.clone(),
        action: Action::Request,
    };
    let answer_msg = Message {
        tag: t.vcbc.tag.clone(),
        action: Action::Answer(t.m(), sig),
    };

    t.vcbc
        .receive_message(TestNet::PARTY_S, request_msg, &mut t.broadcaster)
        .unwrap();

    assert!(t.is_send_to(&TestNet::PARTY_S, &answer_msg));
}

#[test]
fn test_c_answer() {
    let i = TestNet::PARTY_X;
    let j = TestNet::PARTY_S;
    let mut t = TestNet::new(i, j);

    let sig = t.u();
    let answer_msg = Message {
        tag: t.vcbc.tag.clone(),
        action: Action::Answer(t.m(), sig),
    };

    t.vcbc
        .receive_message(TestNet::PARTY_S, answer_msg, &mut t.broadcaster)
        .unwrap();

    assert!(t.vcbc.read_delivered().is_some());
}
