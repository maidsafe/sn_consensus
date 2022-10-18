use super::*;
use crate::mvba::{crypto::public::RandomPubKey, proposal};
use minicbor::to_vec;

fn proposal_checker(p: &Proposal) -> bool {
    true
}

fn setup(proposer: PubKey, self_key: PubKey) -> VCBC {
    let parties = vec![
        proposer.clone(),
        self_key.clone(),
        RandomPubKey(),
        RandomPubKey(),
    ];
    let threshold = 1;

    let proposal_checker: ProposalChecker = proposal_checker;
    let broadcaster = Broadcaster::new(&self_key);
    VCBC::new(
        &proposer,
        &parties,
        threshold,
        &proposal_checker,
        Rc::new(RefCell::new(broadcaster)),
    )
}

fn make_payload(tag: &str, proposal: &Proposal) -> Vec<u8> {
    to_vec(Message {
        proposal: proposal.clone(),
        tag: tag.to_string(),
    })
    .unwrap()
}

#[test]
fn test_normal_case() {
    let proposer = RandomPubKey();
    let mut vcbc = setup(proposer.clone(), proposer.clone());
    let parties = vcbc.state.as_ref().unwrap().context().parties.clone();

    let proposal = &Proposal {
        proposer: proposer,
        value: vec![1],
        proof: vec![1],
    };
    vcbc.propose(&proposal).unwrap();
    vcbc.process_message(&parties[2], &make_payload(message::MSG_TAG_ECHO, proposal))
        .unwrap();
    vcbc.process_message(&parties[3], &make_payload(message::MSG_TAG_ECHO, proposal))
        .unwrap();

    assert!(vcbc.is_delivered())
}
