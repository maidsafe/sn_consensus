use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use blsttc::SecretKeySet;

use crate::mvba::broadcaster::Broadcaster;
use crate::mvba::bundle::Bundle;
use crate::mvba::hash::Hash32;

use super::{NodeId, Vcbc};

use super::message::{Message, Tag};

struct Net {
    secret_key_set: SecretKeySet,
    nodes: BTreeMap<NodeId, Vcbc>,
    queue: BTreeMap<NodeId, Vec<Bundle>>,
}

impl Net {
    fn new(n: usize, tag: Tag) -> Self {
        // we can tolerate < n/3 faults
        let faults = n.saturating_sub(1) / 3;

        // we want to require n - f signature shares but
        // blsttc wants a threshold value where you require t + 1 shares
        // So we just subtract 1 from n - f.
        let threshold = (n - faults).saturating_sub(1);
        let secret_key_set = blsttc::SecretKeySet::random(threshold, &mut rand::thread_rng());
        let public_key_set = secret_key_set.public_keys();
        let bundle_id = 0; // TODO: what is this?

        let nodes = BTreeMap::from_iter((1..=n).into_iter().map(|node_id| {
            let key_share = secret_key_set.secret_key_share(node_id);
            let broadcaster = Rc::new(RefCell::new(Broadcaster::new(
                bundle_id,
                node_id,
                key_share.clone(),
            )));
            let vcbc = Vcbc::new(
                node_id,
                tag.clone(),
                public_key_set.clone(),
                key_share,
                broadcaster,
            );
            (node_id, vcbc)
        }));

        Net {
            secret_key_set,
            nodes,
            queue: Default::default(),
        }
    }

    fn node_mut(&mut self, id: NodeId) -> &mut Vcbc {
        self.nodes.get_mut(&id).unwrap()
    }

    fn enqueue_bundles_from(&mut self, id: NodeId) {
        let (send_bundles, bcast_bundles) = {
            let mut broadcaster = self.node_mut(id).broadcaster.borrow_mut();
            let send_bundles = broadcaster.take_send_bundles();
            let bcast_bundles = broadcaster.take_broadcast_bundles();
            (send_bundles, bcast_bundles)
        };

        for (recipient, bundle) in send_bundles {
            let bundle: Bundle =
                bincode::deserialize(&bundle).expect("Failed to deserialize bundle");
            self.queue.entry(recipient).or_default().push(bundle);
        }

        for bundle in bcast_bundles {
            for recipient in self.nodes.keys() {
                let bundle: Bundle =
                    bincode::deserialize(&bundle).expect("Failed to deserialize bundle");
                self.queue.entry(*recipient).or_default().push(bundle);
            }
        }
    }

    fn drain_queue(&mut self) {
        while !self.queue.is_empty() {
            for (recipient, queue) in std::mem::take(&mut self.queue) {
                let recipient_node = self.node_mut(recipient);

                for bundle in queue {
                    let msg: Message = bincode::deserialize(&bundle.message)
                        .expect("Failed to deserialize message");

                    recipient_node
                        .receive_message(bundle.sender, msg)
                        .expect("Failed to receive msg");
                }

                self.enqueue_bundles_from(recipient);
            }
        }
    }
}

#[test]
fn test_vcbc_happy_path() {
    let proposer = 1;
    let tag = Tag::new("happy-path-test", proposer, 0);
    let mut net = Net::new(7, tag.clone());

    // Node 1 (the proposer) will initiate VCBC by broadcasting a value

    let proposer_node = net.node_mut(proposer);
    proposer_node.c_broadcast("HAPPY-PATH-VALUE".as_bytes().to_vec());

    net.enqueue_bundles_from(proposer);

    // Now we roll-out the simulation to completion.

    net.drain_queue();

    // And check that all nodes have delivered the expected value and signature

    let expected_bytes_to_sign: Vec<u8> = bincode::serialize(&(
        tag,
        "c-ready",
        Hash32::calculate("HAPPY-PATH-VALUE".as_bytes()),
    ))
    .expect("Failed to serialize");

    let expected_sig = net
        .secret_key_set
        .secret_key()
        .sign(&expected_bytes_to_sign);

    for (_, node) in net.nodes {
        assert_eq!(
            node.read_delivered(),
            Some(("HAPPY-PATH-VALUE".as_bytes().to_vec(), expected_sig.clone()))
        )
    }
}

// use crate::mvba::vcbc::error::Error;
// use blsttc::SecretKeySet;
// use rand::{random, thread_rng, Rng};

// struct TestData {
//     vcbc: Vcbc,
//     broadcaster: Rc<RefCell<Broadcaster>>,
//     proposal: Proposal,
// }

// fn valid_proposal(_: &Proposal) -> bool {
//     true
// }

// fn invalid_proposal(_: &Proposal) -> bool {
//     false
// }

// impl TestData {
//     const PARTY_X: NodeId = 0;
//     const PARTY_Y: NodeId = 1;
//     const PARTY_B: NodeId = 2;
//     const PARTY_S: NodeId = 3;

//     // There are 4 parties: X, Y, B, S (B is Byzantine and S is Slow)
//     // The VCBC test instance is created for party X.
//     pub fn new(proposer_id: NodeId) -> Self {
//         let mut rng = thread_rng();
//         let sec_key_set = SecretKeySet::random(4, &mut rng);
//         let proposer_key = sec_key_set.secret_key_share(proposer_id);
//         let broadcaster = Rc::new(RefCell::new(Broadcaster::new(
//             random(),
//             &proposer_key,
//             Some(Self::PARTY_X),
//         )));
//         let vcbc = Vcbc::new(4, 1, proposer_id, broadcaster.clone(), valid_proposal);

//         // Creating a random proposal
//         let mut rng = rand::thread_rng();
//         let proposal = Proposal {
//             proposer_id,
//             value: (0..100).map(|_| rng.gen_range(0..64)).collect(),
//             proof: (0..100).map(|_| rng.gen_range(0..64)).collect(),
//         };

//         Self {
//             vcbc,
//             broadcaster,
//             proposal,
//         }
//     }

//     pub fn propose_msg(&self) -> Message {
//         Message::Propose(self.proposal.clone())
//     }

//     pub fn echo_msg(&self) -> Message {
//         Message::Echo(self.proposal.clone())
//     }

//     pub fn is_proposed(&self) -> bool {
//         self.broadcaster.borrow().has_message(&self.propose_msg())
//     }
//     pub fn is_echoed(&self) -> bool {
//         self.broadcaster.borrow().has_message(&self.echo_msg())
//     }
// }

// #[test]
// fn test_should_propose() {
//     let mut t = TestData::new(TestData::PARTY_X);

//     t.vcbc.propose(&t.proposal).unwrap();

//     assert!(t.is_proposed());
//     assert!(t.is_echoed());
//     assert!(t.vcbc.ctx.echos.contains(&TestData::PARTY_X));
// }

// #[test]
// fn test_should_not_propose() {
//     let mut t = TestData::new(TestData::PARTY_S);

//     t.vcbc
//         .process_message(&TestData::PARTY_Y, &t.echo_msg())
//         .unwrap();

//     assert!(!t.is_proposed());
//     assert!(t.is_echoed());
// }

// #[test]
// fn test_normal_case() {
//     let mut t = TestData::new(TestData::PARTY_X);

//     assert!(!t.vcbc.is_delivered());
//     assert_eq!(t.vcbc.ctx.proposal, None);
//     assert!(t.vcbc.ctx.echos.is_empty());

//     t.vcbc.propose(&t.proposal).unwrap();
//     t.vcbc
//         .process_message(&TestData::PARTY_Y, &t.echo_msg())
//         .unwrap();
//     t.vcbc
//         .process_message(&TestData::PARTY_S, &t.echo_msg())
//         .unwrap();

//     assert!(t.vcbc.is_delivered());
//     assert_eq!(t.vcbc.ctx.proposal, Some(t.proposal.clone()));
//     assert!(&t.vcbc.ctx.echos.contains(&TestData::PARTY_X));
//     assert!(&t.vcbc.ctx.echos.contains(&TestData::PARTY_Y));
//     assert!(&t.vcbc.ctx.echos.contains(&TestData::PARTY_S));
// }

// #[test]
// fn test_delayed_propose_message() {
//     let mut t = TestData::new(TestData::PARTY_S);

//     t.vcbc
//         .process_message(&TestData::PARTY_Y, &t.echo_msg())
//         .unwrap();
//     t.vcbc
//         .process_message(&TestData::PARTY_S, &t.echo_msg())
//         .unwrap();

//     assert!(t.vcbc.is_delivered());

//     // Receiving propose message now
//     t.broadcaster.borrow_mut().clear();
//     t.vcbc
//         .process_message(&TestData::PARTY_S, &t.propose_msg())
//         .unwrap();

//     assert!(!t.is_echoed());
// }

// #[test]
// fn test_invalid_proposal() {
//     let mut t = TestData::new(TestData::PARTY_B);
//     t.vcbc.ctx.proposal_checker = invalid_proposal;

//     assert_eq!(
//         t.vcbc
//             .process_message(&TestData::PARTY_B, &t.propose_msg())
//             .err(),
//         Some(Error::InvalidProposal(t.proposal)),
//     );
// }

// #[test]
// fn test_duplicated_proposal() {
//     let mut t = TestData::new(TestData::PARTY_B);

//     // Party_x receives a proposal from party_b
//     t.vcbc
//         .process_message(&TestData::PARTY_B, &t.propose_msg())
//         .unwrap();

//     // Party_x receives an echo message from from party_s
//     // that echoes different proposal
//     let mut rng = rand::thread_rng();
//     let duplicated_proposal = Proposal {
//         proposer_id: t.proposal.proposer_id,
//         value: (0..100).map(|_| rng.gen_range(0..64)).collect(),
//         proof: (0..100).map(|_| rng.gen_range(0..64)).collect(),
//     };
//     let msg = Message::Propose(duplicated_proposal.clone());

//     assert_eq!(
//         t.vcbc.process_message(&TestData::PARTY_B, &msg).err(),
//         Some(Error::DuplicatedProposal(duplicated_proposal)),
//     );
// }
