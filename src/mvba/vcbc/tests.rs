use super::*;
use crate::mvba::vcbc::error::Error;
use blsttc::SecretKeySet;
use rand::{random, thread_rng, Rng};

struct TestData {
    vcbc: Vcbc,
    broadcaster: Rc<RefCell<Broadcaster>>,
    proposal: Proposal,
}

fn valid_proposal(_: &Proposal) -> bool {
    true
}

fn invalid_proposal(_: &Proposal) -> bool {
    false
}

impl TestData {
    const PARTY_X: NodeId = 0;
    const PARTY_Y: NodeId = 1;
    const PARTY_B: NodeId = 2;
    const PARTY_S: NodeId = 3;

    // There are 4 parties: X, Y, B, S (B is Byzantine and S is Slow)
    // The VCBC test instance is created for party X.
    pub fn new(proposer_id: NodeId) -> Self {
        let mut rng = thread_rng();
        let sec_key_set = SecretKeySet::random(4, &mut rng);
        let proposer_key = sec_key_set.secret_key_share(proposer_id);
        let broadcaster = Rc::new(RefCell::new(Broadcaster::new(
            random(),
            &proposer_key,
            Some(Self::PARTY_X),
        )));
        let vcbc = Vcbc::new(
            vec![Self::PARTY_X, Self::PARTY_Y, Self::PARTY_B, Self::PARTY_S],
            proposer_id,
            1,
            broadcaster.clone(),
            valid_proposal,
        );

        // Creating a random proposal
        let mut rng = rand::thread_rng();
        let proposal = Proposal {
            proposer_id,
            value: (0..100).map(|_| rng.gen_range(0..64)).collect(),
            proof: (0..100).map(|_| rng.gen_range(0..64)).collect(),
        };

        Self {
            vcbc,
            broadcaster,
            proposal,
        }
    }

    pub fn propose_msg(&self) -> Message {
        Message::Propose(self.proposal.clone())
    }

    pub fn echo_msg(&self) -> Message {
        Message::Echo(self.proposal.clone())
    }

    pub fn is_proposed(&self) -> bool {
        self.broadcaster.borrow().has_message(&self.propose_msg())
    }
    pub fn is_echoed(&self) -> bool {
        self.broadcaster.borrow().has_message(&self.echo_msg())
    }
}

#[test]
fn test_should_propose() {
    let mut t = TestData::new(TestData::PARTY_X);

    t.vcbc.propose(&t.proposal).unwrap();

    assert!(t.is_proposed());
    assert!(t.is_echoed());
    assert!(t.vcbc.ctx.echos.contains(&TestData::PARTY_X));
}

#[test]
fn test_should_not_propose() {
    let mut t = TestData::new(TestData::PARTY_S);

    t.vcbc
        .process_message(&TestData::PARTY_Y, t.echo_msg())
        .unwrap();

    assert!(!t.is_proposed());
    assert!(t.is_echoed());
}

#[test]
fn test_normal_case() {
    let mut t = TestData::new(TestData::PARTY_X);

    assert!(!t.vcbc.is_delivered());
    assert_eq!(t.vcbc.ctx.proposal, None);
    assert!(t.vcbc.ctx.echos.is_empty());

    t.vcbc.propose(&t.proposal).unwrap();
    t.vcbc
        .process_message(&TestData::PARTY_Y, t.echo_msg())
        .unwrap();
    t.vcbc
        .process_message(&TestData::PARTY_S, t.echo_msg())
        .unwrap();

    assert!(t.vcbc.is_delivered());
    assert_eq!(t.vcbc.ctx.proposal, Some(t.proposal.clone()));
    assert!(&t.vcbc.ctx.echos.contains(&TestData::PARTY_X));
    assert!(&t.vcbc.ctx.echos.contains(&TestData::PARTY_Y));
    assert!(&t.vcbc.ctx.echos.contains(&TestData::PARTY_S));
}

#[test]
fn test_delayed_propose_message() {
    let mut t = TestData::new(TestData::PARTY_S);

    t.vcbc
        .process_message(&TestData::PARTY_Y, t.echo_msg())
        .unwrap();
    t.vcbc
        .process_message(&TestData::PARTY_S, t.echo_msg())
        .unwrap();

    assert!(t.vcbc.is_delivered());

    // Receiving propose message now
    t.broadcaster.borrow_mut().clear();
    t.vcbc
        .process_message(&TestData::PARTY_S, t.propose_msg())
        .unwrap();

    assert!(!t.is_echoed());
}

#[test]
fn test_invalid_proposal() {
    let mut t = TestData::new(TestData::PARTY_B);
    t.vcbc.ctx.proposal_checker = invalid_proposal;

    assert_eq!(
        t.vcbc
            .process_message(&TestData::PARTY_B, t.propose_msg())
            .err(),
        Some(Error::InvalidProposal(t.proposal)),
    );
}

#[test]
fn test_duplicated_proposal() {
    let mut t = TestData::new(TestData::PARTY_B);

    // Party_x receives a proposal from party_b
    t.vcbc
        .process_message(&TestData::PARTY_B, t.propose_msg())
        .unwrap();

    // Party_x receives an echo message from from party_s
    // that echoes different proposal
    let mut rng = rand::thread_rng();
    let duplicated_proposal = Proposal {
        proposer_id: t.proposal.proposer_id,
        value: (0..100).map(|_| rng.gen_range(0..64)).collect(),
        proof: (0..100).map(|_| rng.gen_range(0..64)).collect(),
    };
    let msg = Message::Propose(duplicated_proposal.clone());

    assert_eq!(
        t.vcbc.process_message(&TestData::PARTY_B, msg).err(),
        Some(Error::DuplicatedProposal(duplicated_proposal)),
    );
}

#[test]
fn test_byzantine_messages() {
    let mut t = TestData::new(TestData::PARTY_B);

    let mut byz_proposal = t.proposal.clone();
    byz_proposal.proposer_id = 66; // unknown proposer
    let msg = Message::Propose(byz_proposal.clone());
    assert_eq!(
        t.vcbc.process_message(&TestData::PARTY_B, msg).err(),
        Some(Error::InvalidProposer(
            TestData::PARTY_B,
            byz_proposal.proposer_id
        ))
    );

    assert_eq!(
        t.vcbc.process_message(&66, t.propose_msg()).err(),
        Some(Error::InvalidSender(66))
    );
}
