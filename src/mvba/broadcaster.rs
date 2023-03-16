use serde::Serialize;

use super::{
    bundle::{self, Bundle, Outgoing},
    NodeId,
};

// Broadcaster holds information required to broadcast the messages.
#[derive(Debug)]
pub struct Broadcaster<P: Serialize> {
    self_id: NodeId,
    outgoings: Vec<Outgoing<P>>,
}

impl<P: Serialize + Eq> Broadcaster<P> {
    pub fn new(self_id: NodeId) -> Self {
        Self {
            self_id,
            outgoings: Vec::new(),
        }
    }

    pub fn send_to(
        &mut self,
        target: Option<NodeId>,
        message: bundle::Message<P>,
        recipient: NodeId,
    ) {
        let bdl = self.make_bundle(target, message);
        self.outgoings.push(Outgoing::Direct(recipient, bdl));
    }

    pub fn broadcast(&mut self, target: Option<NodeId>, message: bundle::Message<P>) {
        let bdl = self.make_bundle(target, message);
        self.outgoings.push(Outgoing::Gossip(bdl));
    }

    fn make_bundle(&self, target: Option<NodeId>, message: bundle::Message<P>) -> Bundle<P> {
        Bundle {
            initiator: self.self_id,
            target,
            message,
        }
    }

    pub fn take_outgoings(&mut self) -> Vec<Outgoing<P>> {
        std::mem::take(&mut self.outgoings)
    }

    #[allow(clippy::type_complexity)]
    #[cfg(test)]
    pub fn take_bundles(&mut self) -> (Vec<Vec<u8>>, Vec<(NodeId, Vec<u8>)>) {
        let mut gossips = Vec::with_capacity(self.outgoings.len());
        let mut directs = Vec::with_capacity(self.outgoings.len());

        for out in std::mem::take(&mut self.outgoings) {
            match out {
                Outgoing::Gossip(bdl) => gossips.push(bincode::serialize(&bdl).unwrap()),
                Outgoing::Direct(recipient, bdl) => {
                    directs.push((recipient, bincode::serialize(&bdl).unwrap()))
                }
            }
        }
        (gossips, directs)
    }

    #[cfg(test)]
    pub fn has_gossip_message(&self, msg: &bundle::Message<P>) -> bool {
        for out in &self.outgoings {
            if let Outgoing::Gossip(bdl) = out {
                if &bdl.message == msg {
                    return true;
                }
            }
        }
        false
    }

    #[cfg(test)]
    pub fn has_direct_message(&self, to: &NodeId, msg: &bundle::Message<P>) -> bool {
        for out in &self.outgoings {
            if let Outgoing::Direct(recipient, bdl) = out {
                if &bdl.message == msg && recipient == to {
                    return true;
                }
            }
        }
        false
    }
}
