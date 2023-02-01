use super::message::{Message, Vote};
use super::NodeId;
use super::{Error, Mvba};
use crate::mvba::broadcaster::Broadcaster;
use crate::mvba::hash::Hash32;
use crate::mvba::vcbc::message::Tag;
use crate::mvba::{vcbc, Proposal};
use blsttc::{SecretKey, SecretKeySet, Signature, SignatureShare};
use rand::{thread_rng, Rng};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

struct TestNet {
    sec_key_set: SecretKeySet,
    mvba: Mvba,
    broadcaster: Rc<RefCell<Broadcaster>>,
    proposals: HashMap<NodeId, (Proposal, Signature)>,
}

impl TestNet {
    const PARTY_X: NodeId = 0;
    const PARTY_Y: NodeId = 1;
    const PARTY_B: NodeId = 2;
    const PARTY_S: NodeId = 3;

    // There are 4 parties: X, Y, B, S (B is Byzantine and S is Slow)
    // The MVBA test instance creates for party `i` with `ID` sets to `test-id`
    // and `tag.s` sets to `0`.
    pub fn new(i: NodeId) -> Self {
        let id = "test-id".to_string();
        let mut rng = thread_rng();
        let sec_key_set = SecretKeySet::random(2, &mut rng);
        let sec_key_share = sec_key_set.secret_key_share(i);
        let broadcaster = Rc::new(RefCell::new(Broadcaster::new(i)));
        let parties = vec![Self::PARTY_X, Self::PARTY_Y, Self::PARTY_B, Self::PARTY_S];
        let mut proposals = HashMap::new();

        for p in &parties {
            let proposal = (0..100).map(|_| rng.gen_range(0..64)).collect();
            let digest = Hash32::calculate(&proposal);
            let tag = Tag::new(&id, *p, 0);
            let proposal_sign_bytes = vcbc::c_ready_bytes_to_sign(&tag, &digest).unwrap();
            let sig = sec_key_set.secret_key().sign(proposal_sign_bytes);

            proposals.insert(*p, (proposal, sig));
        }

        let mvba = Mvba::new(
            id,
            i,
            sec_key_share,
            sec_key_set.public_keys(),
            parties,
            broadcaster.clone(),
        );
        Self {
            sec_key_set,
            mvba,
            broadcaster,
            proposals,
        }
    }

    pub fn make_vote_msg(&self, voter: NodeId, proposer: NodeId, value: bool) -> Message {
        let mut tag = self.mvba.tag();
        tag.proposer = proposer;
        let proof = if !value {
            None
        } else {
            let (proposal, signature) = self.proposals.get(&proposer).unwrap();
            let digest = Hash32::calculate(proposal);
            Some((digest, signature.clone()))
        };

        let vote = Vote { tag, value, proof };
        let signature = self.sign_vote(&vote, &voter);
        Message {
            voter,
            vote,
            signature,
        }
    }

    pub fn is_broadcasted(&self, msg: &Message) -> bool {
        self.broadcaster
            .borrow()
            .has_gossip_message(&bincode::serialize(msg).unwrap())
    }

    fn sign_vote(&self, vote: &Vote, id: &NodeId) -> SignatureShare {
        let data = bincode::serialize(&vote).unwrap();
        let sec_key_share = self.sec_key_set.secret_key_share(id);
        sec_key_share.sign(data)
    }
}

#[test]
fn test_ignore_messages_with_wrong_id() {
    let voter = TestNet::PARTY_B;
    let proposer = TestNet::PARTY_X;
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let mut msg = t.make_vote_msg(voter, proposer, true);
    msg.vote.tag.domain = "another-domain".to_string();

    let result = t.mvba.receive_message(msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == "invalid tag. expected: test-domain.0.0, got another-domain.0.0"));
}

#[test]
fn test_ignore_messages_with_invalid_signature() {
    let voter = TestNet::PARTY_B;
    let proposer = TestNet::PARTY_X;
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let mut msg = t.make_vote_msg(voter, proposer, true);
    msg.signature = t
        .sec_key_set
        .secret_key_share(voter)
        .sign("invalid_message_to_sign");

    let result = t.mvba.receive_message(msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == *"invalid signature"));
}

#[test]
fn test_ignore_messages_no_vote_with_proof() {
    let voter = TestNet::PARTY_B;
    let proposer = TestNet::PARTY_X;
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let mut msg = t.make_vote_msg(voter, proposer, true);
    msg.vote.value = false;
    msg.signature = t.sign_vote(&msg.vote, &voter);

    let result = t.mvba.receive_message(msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == *"no vote with proof"));
}

#[test]
fn test_ignore_messages_yes_vote_without_proof() {
    let voter = TestNet::PARTY_B;
    let proposer = TestNet::PARTY_X;
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let mut msg = t.make_vote_msg(voter, proposer, false);
    msg.vote.value = true;
    msg.signature = t.sign_vote(&msg.vote, &voter);

    let result = t.mvba.receive_message(msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == *"yes vote without proof"));
}

#[test]
fn test_ignore_proposal_with_an_invalid_proof() {
    let voter = TestNet::PARTY_B;
    let proposer = TestNet::PARTY_X;
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let mut msg = t.make_vote_msg(voter, proposer, true);
    let inv_proposal = "invalid_proposal".as_bytes();
    let inv_sig = SecretKey::random().sign(inv_proposal);
    msg.vote.proof = Some((Hash32::calculate(inv_proposal), inv_sig));
    msg.signature = t.sign_vote(&msg.vote, &voter);

    let result = t.mvba.receive_message(msg);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == *"proposal with an invalid proof"));
}

#[test]
fn test_double_vote() {
    let voter = TestNet::PARTY_B;
    let proposer = TestNet::PARTY_X;
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let msg_1 = t.make_vote_msg(voter, proposer, true);
    let msg_2 = t.make_vote_msg(voter, proposer, false);

    t.mvba.receive_message(msg_1).unwrap();
    let result = t.mvba.receive_message(msg_2);
    assert!(matches!(result, Err(Error::InvalidMessage(msg))
        if msg == format!("double vote detected from {voter:?}")));
}

#[test]
fn test_normal_case() {
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    assert!(t.mvba.completed_vote().is_none());

    let proposal_x = t.proposals.get(&TestNet::PARTY_X).unwrap().clone();
    let proposal_y = t.proposals.get(&TestNet::PARTY_Y).unwrap().clone();
    let proposal_s = t.proposals.get(&TestNet::PARTY_S).unwrap().clone();

    let msg_x = t.make_vote_msg(TestNet::PARTY_X, TestNet::PARTY_X, true);
    let msg_y = t.make_vote_msg(TestNet::PARTY_Y, TestNet::PARTY_X, true);
    let msg_s = t.make_vote_msg(TestNet::PARTY_S, TestNet::PARTY_X, true);

    t.mvba
        .set_proposal(TestNet::PARTY_X, proposal_x.0, proposal_x.1)
        .unwrap();
    t.mvba
        .set_proposal(TestNet::PARTY_Y, proposal_y.0, proposal_y.1)
        .unwrap();

    assert!(!t.is_broadcasted(&msg_y));
    t.mvba
        .set_proposal(TestNet::PARTY_S, proposal_s.0, proposal_s.1)
        .unwrap();
    assert!(t.is_broadcasted(&msg_y));

    t.mvba.receive_message(msg_x).unwrap();
    t.mvba.receive_message(msg_s).unwrap();

    assert!(t.mvba.completed_vote().unwrap());
}

#[test]
fn test_normal_case_no_vote() {
    // Node_x is offline
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let proposal_y = t.proposals.get(&TestNet::PARTY_Y).unwrap().clone();
    let proposal_b = t.proposals.get(&TestNet::PARTY_B).unwrap().clone();
    let proposal_s = t.proposals.get(&TestNet::PARTY_S).unwrap().clone();

    let msg_y_proposal_x = t.make_vote_msg(TestNet::PARTY_Y, TestNet::PARTY_X, false);
    let msg_b_proposal_x = t.make_vote_msg(TestNet::PARTY_B, TestNet::PARTY_X, false);
    let msg_s_proposal_x = t.make_vote_msg(TestNet::PARTY_S, TestNet::PARTY_X, false);

    let msg_y_proposal_y = t.make_vote_msg(TestNet::PARTY_Y, TestNet::PARTY_Y, true);
    let msg_b_proposal_y = t.make_vote_msg(TestNet::PARTY_B, TestNet::PARTY_Y, true);
    let msg_s_proposal_y = t.make_vote_msg(TestNet::PARTY_S, TestNet::PARTY_Y, true);

    t.mvba
        .set_proposal(TestNet::PARTY_Y, proposal_y.0, proposal_y.1)
        .unwrap();
    t.mvba
        .set_proposal(TestNet::PARTY_B, proposal_b.0, proposal_b.1)
        .unwrap();
    t.mvba
        .set_proposal(TestNet::PARTY_S, proposal_s.0, proposal_s.1)
        .unwrap();
    assert!(t.is_broadcasted(&msg_y_proposal_x));

    t.mvba.receive_message(msg_b_proposal_x).unwrap();
    t.mvba.receive_message(msg_s_proposal_x).unwrap();

    assert!(!t.mvba.completed_vote().unwrap());

    // Let move to the next proposal
    t.mvba.move_to_next_proposal().unwrap();
    assert!(t.is_broadcasted(&msg_y_proposal_y));

    t.mvba.receive_message(msg_b_proposal_y).unwrap();
    t.mvba.receive_message(msg_s_proposal_y).unwrap();

    assert!(t.mvba.completed_vote().unwrap());
}

#[test]
fn test_request_proposal() {
    let i = TestNet::PARTY_Y;
    let mut t = TestNet::new(i);

    let msg_x = t.make_vote_msg(TestNet::PARTY_X, TestNet::PARTY_X, true);

    t.mvba.receive_message(msg_x).unwrap();

    let tag = Tag::new(t.mvba.domain, TestNet::PARTY_X, 0);
    let data = vcbc::make_c_request_message(tag).unwrap();

    assert!(t
        .broadcaster
        .borrow()
        .has_direct_message(&TestNet::PARTY_X, &data));
}
