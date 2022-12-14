use super::{
    bundle::{Bundle, Outgoing},
    NodeId,
};

// Broadcaster holds information required to broadcast the messages.
pub struct Broadcaster {
    bundle_id: u32,
    self_id: NodeId,
    outgoings: Vec<Outgoing>,
}

impl Broadcaster {
    pub fn new(bundle_id: u32, self_id: NodeId) -> Self {
        Self {
            bundle_id,
            self_id,
            outgoings: Vec::new(),
        }
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    pub fn send_to(&mut self, module: &str, message: Vec<u8>, recipient: NodeId) {
        let bdl = Bundle {
            id: self.bundle_id,
            sender: self.self_id,
            module: module.to_string(),
            message,
        };
        self.outgoings.push(Outgoing::Direct(recipient, bdl));
    }

    pub fn broadcast(&mut self, module: &str, message: Vec<u8>) {
        let bdl = Bundle {
            id: self.bundle_id,
            sender: self.self_id,
            module: module.to_string(),
            message,
        };
        self.outgoings.push(Outgoing::Gossip(bdl));
    }

    pub fn take_outgoings(&mut self) -> Vec<Outgoing> {
        let out = std::mem::take(&mut self.outgoings);
        self.outgoings = Vec::new();
        out
    }

    #[cfg(test)]
    pub fn take_gossip_bundles(&mut self) -> Vec<Vec<u8>> {
        let mut data = Vec::with_capacity(self.outgoings.len());
        for out in std::mem::take(&mut self.outgoings) {
            if let Outgoing::Gossip(bdl) = out {
                data.push(bincode::serialize(&bdl).unwrap())
            }
        }
        data
    }

    #[cfg(test)]
    pub fn take_direct_bundles(&mut self) -> Vec<(NodeId, Vec<u8>)> {
        let mut data = Vec::with_capacity(self.outgoings.len());

        for out in std::mem::take(&mut self.outgoings) {
            if let Outgoing::Direct(recipient, bdl) = out {
                data.push((recipient, bincode::serialize(&bdl).unwrap()))
            }
        }
        data
    }

    #[cfg(test)]
    pub fn has_gossip_message(&self, msg: &[u8]) -> bool {
        for out in &self.outgoings {
            if let Outgoing::Gossip(bdl) = out {
                if bdl.message.eq(&msg) {
                    return true;
                }
            }
        }
        false
    }

    #[cfg(test)]
    pub fn has_direct_message(&self, to: &NodeId, msg: &[u8]) -> bool {
        for out in &self.outgoings {
            if let Outgoing::Direct(recipient, bdl) = out {
                if bdl.message == msg && recipient == to {
                    return true;
                }
            }
        }
        false
    }
}
