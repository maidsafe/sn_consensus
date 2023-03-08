use std::collections::BTreeMap;

use blsttc::SecretKeySet;

use super::{message::Value, Abba};

use crate::mvba::bundle::Message::AbbaMsg;
use crate::mvba::hash::Hash32;
use crate::mvba::tag::{Domain, Tag};
use crate::mvba::{broadcaster::Broadcaster, bundle::Bundle, NodeId};

struct Net {
    tag: Tag,
    secret_key_set: SecretKeySet,
    nodes: BTreeMap<NodeId, (Abba, Broadcaster)>,
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
        let tag = Tag::new(Domain::new("test-domain", 0), proposer);

        let nodes = BTreeMap::from_iter((1..=n).into_iter().map(|node_id| {
            let key_share = secret_key_set.secret_key_share(node_id);
            let broadcaster = Broadcaster::new(node_id);

            let abba = Abba::new(tag.clone(), node_id, public_key_set.clone(), key_share);
            (node_id, (abba, broadcaster))
        }));

        Net {
            tag,
            secret_key_set,
            nodes,
            queue: Default::default(),
        }
    }

    fn node_mut(&mut self, id: NodeId) -> &mut (Abba, Broadcaster) {
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
                let (recipient_node, recepient_broadcaster) = self.node_mut(recipient);

                for bundle in queue {
                    let msg = match bundle.message {
                        AbbaMsg(msg) => msg,
                        _ => panic!("unexpected message"),
                    };

                    println!("Handling message: {msg:?}");
                    recipient_node
                        .receive_message(bundle.initiator, msg, recepient_broadcaster)
                        .expect("Failed to receive msg");
                }

                self.enqueue_bundles_from(recipient);
            }
        }
    }

    #[allow(unused)]
    fn deliver(&mut self, recipient: NodeId, index: usize) {
        if let Some(msgs) = self.queue.get_mut(&recipient) {
            if msgs.is_empty() {
                return;
            }
            let index = index % msgs.len();

            let bundle = msgs.swap_remove(index);
            let msg = match bundle.message {
                AbbaMsg(msg) => msg,
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
fn test_net_happy_path() {
    let proposer = 1;
    let mut net = Net::new(4, proposer);

    let proposal_digest = Hash32::calculate("test-data".as_bytes());
    let sign_bytes = crate::mvba::vcbc::c_ready_bytes_to_sign(&net.tag, &proposal_digest).unwrap();
    let proposal_sig = net.secret_key_set.secret_key().sign(sign_bytes);

    // All nodes pre-vote one

    for id in Vec::from_iter(net.nodes.keys().copied()) {
        let (node, broadcaster) = net.node_mut(id);

        node.pre_vote_one(proposal_digest, proposal_sig.clone(), broadcaster)
            .expect("Failed to pre-vote");

        net.enqueue_bundles_from(id);
    }

    net.drain_queue();

    for (id, (node, _)) in net.nodes {
        println!("Checking {id}");
        assert_eq!(node.decided_value.unwrap().value, Value::One);
    }
}
