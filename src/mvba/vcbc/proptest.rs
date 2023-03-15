use super::{NodeId, Vcbc};
use crate::mvba::broadcaster::Broadcaster;
use crate::mvba::bundle::Bundle;
use crate::mvba::bundle::Message::Vcbc as VcbcMsg;
use crate::mvba::hash::Hash32;
use crate::mvba::tag::{Domain, Tag};
use crate::mvba::vcbc::c_ready_bytes_to_sign;
use crate::mvba::Proposal;
use blsttc::SecretKeySet;
use quickcheck_macros::quickcheck;
use std::collections::BTreeMap;

fn valid_proposal(_: NodeId, _: &Proposal) -> bool {
    true
}

struct Net {
    domain: Domain,
    secret_key_set: SecretKeySet,
    nodes: BTreeMap<NodeId, (Vcbc, Broadcaster)>,
    queue: BTreeMap<NodeId, Vec<Bundle>>,
}

impl Net {
    fn new(n: usize, proposer: NodeId) -> Self {
        // we can tolerate < n/3 faults
        let faults = n.saturating_sub(1) / 3;

        // we want to require n - f signature shares but
        // blsttc wants a threshold value where you require t + 1 shares
        // So we just subtract 1 from n - f.
        let threshold = (n - faults).saturating_sub(1);
        let secret_key_set = blsttc::SecretKeySet::random(threshold, &mut rand::thread_rng());
        let public_key_set = secret_key_set.public_keys();
        let domain = Domain::new("testing-vcbc", 0);

        let nodes = BTreeMap::from_iter((1..=n).map(|self_id| {
            let key_share = secret_key_set.secret_key_share(self_id);
            let broadcaster = Broadcaster::new(self_id);

            let tag = Tag::new(domain.clone(), proposer);
            let vcbc = Vcbc::new(
                tag,
                self_id,
                public_key_set.clone(),
                key_share,
                valid_proposal,
            );
            (self_id, (vcbc, broadcaster))
        }));

        Net {
            domain,
            secret_key_set,
            nodes,
            queue: Default::default(),
        }
    }

    fn node_mut(&mut self, id: NodeId) -> &mut (Vcbc, Broadcaster) {
        self.nodes.get_mut(&id).unwrap()
    }

    fn enqueue_bundles_from(&mut self, id: NodeId) {
        let (send_bundles, bcast_bundles) = {
            let (_, broadcaster) = self.node_mut(id);
            let (bcast_bundles, send_bundles) = broadcaster.take_bundles();
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
                let (recipient_node, recipient_broadcaster) = self.node_mut(recipient);

                for bundle in queue {
                    let msg = match bundle.message {
                        VcbcMsg(msg) => msg,
                        _ => panic!("unexpected message"),
                    };

                    recipient_node
                        .receive_message(bundle.initiator, msg, recipient_broadcaster)
                        .expect("Failed to receive msg");
                }

                self.enqueue_bundles_from(recipient);
            }
        }
    }

    fn deliver(&mut self, recipient: NodeId, index: usize) {
        if let Some(msgs) = self.queue.get_mut(&recipient) {
            if msgs.is_empty() {
                return;
            }
            let index = index % msgs.len();

            let bundle = msgs.swap_remove(index);
            let msg = match bundle.message {
                VcbcMsg(msg) => msg,
                _ => panic!("unexpected message"),
            };

            let (recipient_node, recipient_broadcaster) = self.node_mut(recipient);
            recipient_node
                .receive_message(bundle.initiator, msg, recipient_broadcaster)
                .expect("Failed to receive message");
            self.enqueue_bundles_from(recipient);
        }
    }
}

#[test]
fn test_vcbc_happy_path() {
    let proposer = 1;
    let mut net = Net::new(7, proposer);

    let tag = Tag::new(net.domain.clone(), proposer);

    // Node 1 (the proposer) will initiate VCBC by broadcasting a value

    let (node, broadcaster) = net.node_mut(proposer);

    node.c_broadcast("HAPPY-PATH-VALUE".as_bytes().to_vec(), broadcaster)
        .expect("Failed to c-broadcast");

    net.enqueue_bundles_from(proposer);

    // Now we roll-out the simulation to completion.

    net.drain_queue();

    // And check that all nodes have delivered the expected value and signature

    let expected_bytes_to_sign: Vec<u8> =
        c_ready_bytes_to_sign(&tag, &Hash32::calculate("HAPPY-PATH-VALUE"))
            .expect("Failed to serialize");

    let expected_sig = net.secret_key_set.secret_key().sign(expected_bytes_to_sign);

    for (_, (node, _)) in net.nodes {
        assert_eq!(
            node.read_delivered(),
            Some(("HAPPY-PATH-VALUE".as_bytes().to_vec(), expected_sig.clone()))
        )
    }
}

#[quickcheck]
fn prop_vcbc_terminates_under_randomized_msg_delivery(
    n: usize,
    proposer: usize,
    proposal: Vec<u8>,
    msg_order: Vec<(NodeId, usize)>,
) {
    let n = n % 10 + 1; // Large n is wasteful, and n must be > 0
    let proposer = proposer % n + 1; // NodeId's start at 1
    let mut net = Net::new(n, proposer);

    // First the proposer will initiate VCBC by broadcasting the proposal:
    let (proposer_node, proposer_broadcaster) = net.node_mut(proposer);
    proposer_node
        .c_broadcast(proposal.clone(), proposer_broadcaster)
        .expect("Failed to c-broadcast");

    net.enqueue_bundles_from(proposer);

    // Next we deliver the messages in the order chosen by quickcheck
    for (recipient, msg_index) in msg_order {
        net.deliver(recipient, msg_index);
    }

    // Then we roll-out the simulation to completion.
    net.drain_queue();

    // And finally, check that all nodes have delivered the expected value and signature

    let tag = Tag::new(net.domain.clone(), proposer);
    let expected_bytes_to_sign: Vec<u8> =
        c_ready_bytes_to_sign(&tag, &Hash32::calculate(&proposal)).expect("Failed to serialize");

    let expected_sig = net.secret_key_set.secret_key().sign(expected_bytes_to_sign);

    for (_, (node, _)) in net.nodes {
        assert_eq!(
            node.read_delivered(),
            Some((proposal.clone(), expected_sig.clone()))
        )
    }
}
