use super::{
    bundle::{Bundle, Outgoing},
    NodeId,
};

// Broadcaster holds information required to broadcast the messages.
#[derive(Debug)]
pub struct Broadcaster {
    self_id: NodeId,
    outgoings: Vec<Outgoing>,
}

impl Broadcaster {
    pub fn new(self_id: NodeId) -> Self {
        Self {
            self_id,
            outgoings: Vec::new(),
        }
    }

    pub fn send_to(
        &mut self,
        module: &str,
        target: Option<NodeId>,
        payload: Vec<u8>,
        recipient: NodeId,
    ) {
        let bdl = self.make_bundle(module, target, payload);
        self.outgoings.push(Outgoing::Direct(recipient, bdl));
    }

    pub fn broadcast(&mut self, module: &str, target: Option<NodeId>, payload: Vec<u8>) {
        let bdl = self.make_bundle(module, target, payload);
        self.outgoings.push(Outgoing::Gossip(bdl));
    }

    fn make_bundle(&self, module: &str, target: Option<NodeId>, payload: Vec<u8>) -> Bundle {
        Bundle {
            initiator: self.self_id,
            target,
            module: module.to_string(),
            payload,
        }
    }

    pub fn take_outgoings(&mut self) -> Vec<Outgoing> {
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
    pub fn has_gossip_message(&self, pld: &[u8]) -> bool {
        for out in &self.outgoings {
            if let Outgoing::Gossip(bdl) = out {
                if bdl.payload.eq(&pld) {
                    return true;
                }
            }
        }
        false
    }

    #[cfg(test)]
    pub fn has_direct_message(&self, to: &NodeId, pld: &[u8]) -> bool {
        for out in &self.outgoings {
            if let Outgoing::Direct(recipient, bdl) = out {
                if bdl.payload == pld && recipient == to {
                    return true;
                }
            }
        }
        false
    }
}
